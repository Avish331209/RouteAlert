"""
database.py - SQLite Database management for RouteAlert.
Manages connections, schema initialization, timestamps in Asia/Kolkata,
and all parameterized database queries.
"""

import os
import sqlite3
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from werkzeug.security import generate_password_hash, check_password_hash

# Timezone configuration: Salem, Tamil Nadu, India is in Asia/Kolkata
KOLKATA_TZ = ZoneInfo("Asia/Kolkata")

# Predefined domain constants
CATEGORIES = [
    "Delay",
    "Route Diversion",
    "Cancellation",
    "Service Disruption"
]

REASONS = [
    "Heavy Rain",
    "Festival Traffic",
    "Roadwork",
    "Traffic Congestion",
    "Roadblock",
    "Other"
]

STATUSES = [
    "Active",
    "Resolved",
    "Expired"
]

VERIFICATION_STATUSES = [
    "Verified",
    "Unverified"
]

DEFAULT_DB_PATH = os.environ.get("DATABASE_PATH", "routealert.db")


def get_current_kolkata_datetime() -> datetime:
    """Return the current datetime in the Asia/Kolkata timezone."""
    return datetime.now(KOLKATA_TZ)


def get_current_kolkata_iso() -> str:
    """Return current timestamp string in ISO 8601 format with Asia/Kolkata offset."""
    return datetime.now(KOLKATA_TZ).isoformat()


def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """
    Establish and return a SQLite connection with Row factory enabled
    and foreign key constraints enforced.
    """
    path = db_path or os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = None) -> None:
    """
    Create the SQLite database tables and indexes automatically.
    Safe to call multiple times (idempotent).
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    route_number TEXT,
                    affected_area TEXT NOT NULL,
                    bus_stop TEXT,
                    category TEXT NOT NULL CHECK(category IN (
                        'Delay', 'Route Diversion', 'Cancellation', 'Service Disruption'
                    )),
                    reason TEXT NOT NULL CHECK(reason IN (
                        'Heavy Rain', 'Festival Traffic', 'Roadwork',
                        'Traffic Congestion', 'Roadblock', 'Other'
                    )),
                    description TEXT NOT NULL,
                    estimated_delay_minutes INTEGER CHECK(
                        estimated_delay_minutes IS NULL OR estimated_delay_minutes >= 0
                    ),
                    alternative_route TEXT,
                    source_name TEXT,
                    source_url TEXT,
                    verification_status TEXT NOT NULL DEFAULT 'Unverified' CHECK(
                        verification_status IN ('Verified', 'Unverified')
                    ),
                    status TEXT NOT NULL DEFAULT 'Active' CHECK(
                        status IN ('Active', 'Resolved', 'Expired')
                    ),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT
                );
            """)

            # Indexes for alerts table for query performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_reason ON alerts(reason);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_route ON alerts(route_number);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_area ON alerts(affected_area);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);")

            # 2. Admin users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);")
    finally:
        conn.close()


def auto_expire_alerts(db_path: str = None, conn: sqlite3.Connection = None) -> int:
    """
    Automatically marks Active alerts whose expires_at timestamp has passed as Expired.
    Returns the number of alerts updated.
    """
    should_close = False
    if conn is None:
        conn = get_db_connection(db_path)
        should_close = True

    now_iso = get_current_kolkata_iso()
    try:
        with conn:
            cursor = conn.execute("""
                UPDATE alerts
                SET status = 'Expired',
                    updated_at = ?
                WHERE status = 'Active'
                  AND expires_at IS NOT NULL
                  AND expires_at != ''
                  AND expires_at <= ?
            """, (now_iso, now_iso))
            return cursor.rowcount
    finally:
        if should_close:
            conn.close()


def create_admin_user(username: str, password: str, db_path: str = None) -> int:
    """
    Safely creates a new administrator with a Werkzeug-hashed password.
    Raises ValueError if username or password is invalid or already exists.
    """
    username = (username or "").strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        raise ValueError("Username may only contain letters, numbers, hyphens, underscores, or periods.")
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")

    password_hash = generate_password_hash(password, method="scrypt")
    now_iso = get_current_kolkata_iso()

    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO admin_users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            """, (username, password_hash, now_iso))
            return cursor.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"Admin user '{username}' already exists.")
    finally:
        conn.close()


def get_admin_by_username(username: str, db_path: str = None) -> dict:
    """Fetch an admin user by username, or None if not found."""
    if not username:
        return None
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM admin_users WHERE username = ?",
            (username.strip(),)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_admin_by_id(admin_id: int, db_path: str = None) -> dict:
    """Fetch an admin user by ID, or None if not found."""
    if not admin_id:
        return None
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM admin_users WHERE id = ?",
            (admin_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_dashboard_counts(db_path: str = None) -> dict:
    """
    Calculate and return the dashboard counts dynamically from the database:
    - Active Alerts
    - Bus Delays (Active alerts with category 'Delay')
    - Route Diversions (Active alerts with category 'Route Diversion')
    - Resolved Alerts (Alerts with status 'Resolved')
    """
    auto_expire_alerts(db_path)
    conn = get_db_connection(db_path)
    try:
        # Active Alerts
        active_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'Active'"
        ).fetchone()[0]

        # Bus Delays (Active)
        delay_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE category = 'Delay' AND status = 'Active'"
        ).fetchone()[0]

        # Route Diversions (Active)
        diversion_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE category = 'Route Diversion' AND status = 'Active'"
        ).fetchone()[0]

        # Resolved Alerts
        resolved_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'"
        ).fetchone()[0]

        return {
            "active_alerts": active_count,
            "bus_delays": delay_count,
            "route_diversions": diversion_count,
            "resolved_alerts": resolved_count
        }
    finally:
        conn.close()


def get_alerts(
    search: str = None,
    route_number: str = None,
    area: str = None,
    category: str = None,
    reason: str = None,
    status: str = None,
    db_path: str = None
) -> list:
    """
    Fetch alerts based on parameterized search terms and filters.
    Orders alerts so Active alerts appear first, followed by newest alerts.
    """
    auto_expire_alerts(db_path)
    conn = get_db_connection(db_path)
    try:
        conditions = []
        params = []

        # Unified search term (matches route, area, bus stop, title, description)
        if search and search.strip():
            term = f"%{search.strip()}%"
            conditions.append("""(
                title LIKE ? OR
                description LIKE ? OR
                route_number LIKE ? OR
                affected_area LIKE ? OR
                bus_stop LIKE ? OR
                alternative_route LIKE ?
            )""")
            params.extend([term, term, term, term, term, term])

        # Specific route number filter
        if route_number and route_number.strip():
            term = f"%{route_number.strip()}%"
            conditions.append("route_number LIKE ?")
            params.append(term)

        # Specific area / bus stop filter
        if area and area.strip():
            term = f"%{area.strip()}%"
            conditions.append("(affected_area LIKE ? OR bus_stop LIKE ?)")
            params.extend([term, term])

        # Category filter
        if category and category.strip() and category != "all":
            conditions.append("category = ?")
            params.append(category.strip())

        # Reason filter
        if reason and reason.strip() and reason != "all":
            conditions.append("reason = ?")
            params.append(reason.strip())

        # Status filter
        if status and status.strip() and status != "all":
            conditions.append("status = ?")
            params.append(status.strip())

        query = "SELECT * FROM alerts"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Sort: Active alerts first, then newest updated/created
        query += """ ORDER BY 
            CASE status 
                WHEN 'Active' THEN 1 
                WHEN 'Resolved' THEN 2 
                ELSE 3 
            END ASC,
            datetime(created_at) DESC,
            id DESC
        """

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_alert_by_id(alert_id: int, db_path: str = None) -> dict:
    """Retrieve an alert by its ID, or None if not found."""
    if not alert_id:
        return None
    auto_expire_alerts(db_path)
    conn = get_db_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_alert(
    title: str,
    affected_area: str,
    category: str,
    reason: str,
    description: str,
    route_number: str = None,
    bus_stop: str = None,
    estimated_delay_minutes: int = None,
    alternative_route: str = None,
    source_name: str = None,
    source_url: str = None,
    verification_status: str = "Unverified",
    status: str = "Active",
    expires_at: str = None,
    db_path: str = None
) -> int:
    """
    Insert a new alert into the database using parameterized SQL.
    Returns the newly created alert's ID.
    """
    now_iso = get_current_kolkata_iso()
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO alerts (
                    title,
                    route_number,
                    affected_area,
                    bus_stop,
                    category,
                    reason,
                    description,
                    estimated_delay_minutes,
                    alternative_route,
                    source_name,
                    source_url,
                    verification_status,
                    status,
                    created_at,
                    updated_at,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title,
                route_number,
                affected_area,
                bus_stop,
                category,
                reason,
                description,
                estimated_delay_minutes,
                alternative_route,
                source_name,
                source_url,
                verification_status,
                status,
                now_iso,
                now_iso,
                expires_at
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def update_alert(
    alert_id: int,
    title: str,
    affected_area: str,
    category: str,
    reason: str,
    description: str,
    route_number: str = None,
    bus_stop: str = None,
    estimated_delay_minutes: int = None,
    alternative_route: str = None,
    source_name: str = None,
    source_url: str = None,
    verification_status: str = "Unverified",
    status: str = "Active",
    expires_at: str = None,
    db_path: str = None
) -> bool:
    """
    Update an existing alert record with new details and update timestamp.
    Returns True if an alert was updated, False otherwise.
    """
    now_iso = get_current_kolkata_iso()
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                UPDATE alerts SET
                    title = ?,
                    route_number = ?,
                    affected_area = ?,
                    bus_stop = ?,
                    category = ?,
                    reason = ?,
                    description = ?,
                    estimated_delay_minutes = ?,
                    alternative_route = ?,
                    source_name = ?,
                    source_url = ?,
                    verification_status = ?,
                    status = ?,
                    updated_at = ?,
                    expires_at = ?
                WHERE id = ?
            """, (
                title,
                route_number,
                affected_area,
                bus_stop,
                category,
                reason,
                description,
                estimated_delay_minutes,
                alternative_route,
                source_name,
                source_url,
                verification_status,
                status,
                now_iso,
                expires_at,
                alert_id
            ))
            return cursor.rowcount > 0
    finally:
        conn.close()


def set_alert_status(alert_id: int, new_status: str, db_path: str = None) -> bool:
    """Set the status of an alert (e.g. 'Resolved', 'Expired', 'Active')."""
    if new_status not in STATUSES:
        raise ValueError(f"Invalid status: {new_status}")
    now_iso = get_current_kolkata_iso()
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                UPDATE alerts
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (new_status, now_iso, alert_id))
            return cursor.rowcount > 0
    finally:
        conn.close()


def set_alert_verification(alert_id: int, new_verification: str, db_path: str = None) -> bool:
    """Set the verification status of an alert ('Verified' or 'Unverified')."""
    if new_verification not in VERIFICATION_STATUSES:
        raise ValueError(f"Invalid verification status: {new_verification}")
    now_iso = get_current_kolkata_iso()
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                UPDATE alerts
                SET verification_status = ?, updated_at = ?
                WHERE id = ?
            """, (new_verification, now_iso, alert_id))
            return cursor.rowcount > 0
    finally:
        conn.close()


def delete_alert(alert_id: int, db_path: str = None) -> bool:
    """Delete an alert record by ID."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    # Command-line helper to initialize DB or create admin
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        if len(sys.argv) == 4:
            u, p = sys.argv[2], sys.argv[3]
        else:
            import getpass
            u = input("Admin username: ")
            p = getpass.getpass("Admin password: ")
        init_db()
        try:
            admin_id = create_admin_user(u, p)
            print(f"Admin user '{u}' created successfully with ID {admin_id}.")
        except Exception as e:
            print(f"Error creating admin: {e}")
    else:
        init_db()
        print("Database initialized successfully.")
