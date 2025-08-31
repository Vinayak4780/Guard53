"""
Supervisor routes for QR location management and guard oversight
SUPERVISOR role only - manage QR locations, view assigned guards, and access scan data
"""

from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import io
import os
from bson import ObjectId

# Import services and dependencies
from services.auth_service import get_current_supervisor
from services.tomtom_service import tomtom_service
#from services.excel_service import excel_service
from database import (
    get_supervisors_collection, get_guards_collection, get_qr_locations_collection,
    get_scan_events_collection, get_users_collection
)
from config import settings

# Configure logging
logger = logging.getLogger(__name__)

# Create router
supervisor_router = APIRouter()



# ============================================================================
# NEW: Supervisor Add Building API
# ============================================================================
from fastapi import Body

@supervisor_router.post("/building/add")
async def add_building(
    building_name: str = Body(..., embed=True, description="Name of the new building to add."),
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    Supervisor-only: Add a new building to the system. Sites and QR codes are handled separately.
    """
    qr_locations_collection = get_qr_locations_collection()
    if qr_locations_collection is None:
        raise HTTPException(status_code=503, detail="Database not available")

    # Check if building already exists for this supervisor
    existing = await qr_locations_collection.find_one({
        "organization": building_name,
        "supervisorId": current_supervisor["_id"]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Building already exists for this supervisor")

    # Add building record (no site field)
    building_data = {
        "organization": building_name,
        "createdBy": str(current_supervisor["_id"]),
        "createdAt": datetime.now(),
        "supervisorId": current_supervisor["_id"]
    }
    result = await qr_locations_collection.insert_one(building_data)
    building_id = str(result.inserted_id)

    return {"building_id": building_id, "organization": building_name, "message": "Building added successfully. Add sites and generate QR codes using the QR code API."}

    # --- The following code should be inside get_supervisor_dashboard, not add_building ---

@supervisor_router.get("/dashboard")
async def get_supervisor_dashboard(current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)):
    supervisors_collection = get_supervisors_collection()
    guards_collection = get_guards_collection()
    qr_locations_collection = get_qr_locations_collection()
    scan_events_collection = get_scan_events_collection()

    if (supervisors_collection is None or guards_collection is None or 
        qr_locations_collection is None or scan_events_collection is None):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not available"
        )

    supervisor_user_id = str(current_supervisor["_id"])
    supervisor_state = current_supervisor["areaCity"]

    # Get assigned guards count (guards assigned to this supervisor)
    assigned_guards = await guards_collection.count_documents({
        "supervisorId": ObjectId(supervisor_user_id)
    })

    # Get QR locations count  
    qr_locations = await qr_locations_collection.count_documents({
        "supervisorId": ObjectId(supervisor_user_id)
    })

    # Filter scans by supervisor's state - look for scans with addresses containing the state
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Build scan filter for supervisor's specific state (e.g., "Maharashtra")
    state_filter = {
        "$or": [
            {"address": {"$regex": supervisor_state, "$options": "i"}},
            {"formatted_address": {"$regex": supervisor_state, "$options": "i"}}
        ]
    }

    # Get today's scan statistics for this state
    today_state_filter = {
        "$and": [
            {"scannedAt": {"$gte": today_start}},
            state_filter
        ]
    }
    today_scans = await scan_events_collection.count_documents(today_state_filter)

    # Get this week's scan statistics for this state
    week_start = today_start - timedelta(days=today_start.weekday())
    week_state_filter = {
        "$and": [
            {"scannedAt": {"$gte": week_start}},
            state_filter
        ]
    }
    this_week_scans = await scan_events_collection.count_documents(week_state_filter)

    # Get recent scan events - only from supervisor's state
    recent_scans_cursor = scan_events_collection.find(state_filter).sort("scannedAt", -1).limit(10)
    recent_scans = await recent_scans_cursor.to_list(length=None)

    # Get guards with most activity - only from supervisor's state
    guard_activity_pipeline = [
        {"$match": {
            "$and": [
                {"scannedAt": {"$gte": week_start}},
                state_filter
            ]
        }},
        {"$group": {
            "_id": "$guardEmail",
            "scan_count": {"$sum": 1}
        }},
        {"$sort": {"scan_count": -1}},
        {"$limit": 5},
        {"$project": {
            "guard_email": "$_id",
            "scan_count": 1,
            "_id": 0
        }}
    ]
    guard_activity = await scan_events_collection.aggregate(guard_activity_pipeline).to_list(length=None)

    # Guard activity already has proper structure, no ObjectId conversion needed

    return {
        "statistics": {
            "assigned_guards": assigned_guards,
            "qr_locations": qr_locations,
            "today_scans": today_scans,
            "this_week_scans": this_week_scans
        },
        "recent_scans": [
            {
                "id": str(scan["_id"]),
                "guard_email": scan.get("guardEmail", ""),
                "guard_id": str(scan.get("guardId", "")),
                "qr_id": scan.get("qrId", ""),
                "original_scan_content": scan.get("originalScanContent", ""),
                "location_name": scan.get("locationName", "Unknown Location"),
                "scanned_at": scan.get("scannedAt"),
                "timestamp": scan.get("timestampIST", ""),
                "device_lat": scan.get("deviceLat", 0),
                "device_lng": scan.get("deviceLng", 0),
                "address": scan.get("address", ""),
                "formatted_address": scan.get("formatted_address", ""),
                "address_lookup_success": scan.get("address_lookup_success", False)
            }
            for scan in recent_scans
        ],
        "guard_activity": guard_activity,
        "area_info": {
            "state": supervisor_state,
            "assigned_area": current_supervisor["areaCity"],
            "state_full": current_supervisor.get("areaState"),
            "country": current_supervisor.get("areaCountry")
        }
    }


@supervisor_router.post("/generate-excel-report")
async def generate_excel_report(
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor),
    days_back: int = Query(7, ge=1, le=30, description="Number of days to include in report"),
    building_name: Optional[str] = Query(None, description="Name of the building to filter (optional)")
):
    """
    Generate Excel report of scan data for supervisor's area and send to admin
    """
    try:
        logger.info("Starting Excel report generation...")
        scan_events_collection = get_scan_events_collection()
        if scan_events_collection is None:
            logger.error("Scan events collection is None")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        logger.info(f"Date range: {start_date} to {end_date}")

        # Build query filter
        supervisor_id = current_supervisor["_id"]
        # Try both string and ObjectId for supervisorId filter
        query_filter = {
            "scannedAt": {"$gte": start_date, "$lte": end_date},
            "$or": [
                {"supervisorId": str(supervisor_id)},
                {"supervisorId": supervisor_id}
            ]
        }

        if building_name:
            query_filter["organization"] = building_name

        # Filter scans by supervisor's area and date range
        scans = await scan_events_collection.find(query_filter).to_list(length=None)

        if not scans:
            logger.warning("No scan data found in the specified date range")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan data found in the specified date range"
            )

        # Debug: Log all scan events found by query
        logger.info(f"Scan events found: {scans}")
        # Prepare Excel data
        excel_data = []
        for scan in scans:
            try:
                date_time = scan["scannedAt"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(scan["scannedAt"], "strftime") else str(scan["scannedAt"])
                building = scan.get("organization")
                site = scan.get("site")
                guard_name = scan.get("guardName")
                if not (building and site and guard_name):
                    logger.warning(f"Skipping scan event missing required fields: {scan}")
                    continue
                row_data = {
                    "Date + Time": date_time,
                    "Action": "QR Code Scan",
                    "Building Name": building,
                    "Site Name": site,
                    "Guard Name": guard_name
                }
                excel_data.append(row_data)
            except Exception as e:
                logger.error(f"Error processing scan event: {e}, scan: {scan}")
                continue

        if not excel_data:
            logger.warning("No valid scan data found for Excel report")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No valid scan data found for Excel report"
            )


        # Create Excel file in memory and return as response
        import io
        import pandas as pd
        from fastapi.responses import StreamingResponse

        output = io.BytesIO()
        df = pd.DataFrame(excel_data)
        df.to_excel(output, index=False, sheet_name="Scan Report")
        output.seek(0)

        filename = f"scan_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"
        headers = {
            "Content-Disposition": f"attachment; filename={filename}"
        }
        logger.info(f"Excel report generated successfully in memory: {filename}")
        return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=headers)

    except Exception as e:
        logger.error(f"Error generating Excel report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while generating the report"
        )

