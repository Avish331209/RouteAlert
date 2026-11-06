"""
app.py - Main Flask application for RouteAlert
Salem Bus Delay and Route Diversion Alert System.
"""

import os
import secrets
import hmac
import re
from functools import wraps
from datetime import datetime
from zoneinfo import ZoneInfo
from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    Response
)
from werkzeug.security import check_password_hash

import database
from database import (
    CATEGORIES,
    REASONS,
    STATUSES,
    VERIFICATION_STATUSES,
    KOLKATA_TZ,
    init_db,
    get_dashboard_counts,
    get_alerts,
    get_alert_by_id,
    create_alert,
    update_alert,
    set_alert_status,
    set_alert_verification,
    delete_alert,
    get_admin_by_username,
    create_admin_user,
    auto_expire_alerts
)

# Load environment variables from .env if present
load_dotenv()


def is_valid_url(url: str) -> bool:
    """Validate that a URL starts with http:// or https:// and has a valid structure."""
    if not url:
        return True
    url = url.strip()
    pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ip address
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE
    )
    return bool(pattern.match(url))


def login_required(f):
    """Decorator to require administrator authentication for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            flash("Administrator login required to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def create_app(test_config=None) -> Flask:
    """Flask Application Factory."""
    app = Flask(__name__)

    # Default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "routealert-development-secret-key-change-in-prod"),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "routealert.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # Set to True when running on HTTPS
        CSRF_ENABLED=True
    )

    if test_config:
        app.config.update(test_config)

    # Initialize the database on startup
    with app.app_context():
        init_db(app.config["DATABASE_PATH"])
        # Check if initial admin should be created from environment
        initial_admin = os.environ.get("INITIAL_ADMIN_USERNAME")
        initial_pass = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if initial_admin and initial_pass:
            existing = get_admin_by_username(initial_admin, app.config["DATABASE_PATH"])
            if not existing:
                try:
                    create_admin_user(initial_admin, initial_pass, app.config["DATABASE_PATH"])
                    app.logger.info(f"Initialized admin user: {initial_admin}")
                except Exception as e:
                    app.logger.warning(f"Could not auto-create initial admin: {e}")

    # Jinja Template Filters
    @app.template_filter("kolkata_datetime")
    def kolkata_datetime_filter(value, format_str="%d %b %Y, %I:%M %p IST"):
        """Format an ISO datetime string into readable Indian Standard Time."""
        if not value:
            return "Not specified"
        try:
            if isinstance(value, str):
                dt = datetime.fromisoformat(value)
            elif isinstance(value, datetime):
                dt = value
            else:
                return str(value)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=KOLKATA_TZ)
            else:
                dt = dt.astimezone(KOLKATA_TZ)
            return dt.strftime(format_str)
        except Exception:
            return str(value)

    @app.template_filter("format_delay")
    def format_delay_filter(minutes):
        """Format delay in minutes, or display 'Not available' if unknown."""
        if minutes is None or minutes == "":
            return "Not available"
        try:
            val = int(minutes)
            if val == 0:
                return "On time (0 mins)"
            return f"{val} mins"
        except (ValueError, TypeError):
            return "Not available"

    @app.template_filter("datetime_local")
    def datetime_local_filter(value):
        """Format an ISO datetime string for HTML5 input type='datetime-local'."""
        if not value:
            return ""
        try:
            if isinstance(value, str):
                dt = datetime.fromisoformat(value)
            elif isinstance(value, datetime):
                dt = value
            else:
                return ""
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=KOLKATA_TZ)
            else:
                dt = dt.astimezone(KOLKATA_TZ)
            return dt.strftime("%Y-%m-%dT%H:%M")
        except Exception:
            return ""

    # Context processor to inject common variables into all templates
    @app.context_processor
    def inject_globals():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return {
            "csrf_token": session["_csrf_token"],
            "is_admin_logged_in": "admin_id" in session,
            "admin_username": session.get("admin_username"),
            "CATEGORIES": CATEGORIES,
            "REASONS": REASONS,
            "STATUSES": STATUSES,
            "VERIFICATION_STATUSES": VERIFICATION_STATUSES,
            "current_year": datetime.now(KOLKATA_TZ).year
        }

    # CSRF Protection Hook
    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not app.config.get("CSRF_ENABLED", True):
                return
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            session_token = session.get("_csrf_token")
            if not session_token or not token or not hmac.compare_digest(session_token, token):
                abort(400, description="CSRF token missing or invalid. Please refresh the page and try again.")

    # ---------------------------------------------------------
    # Public Routes
    # ---------------------------------------------------------

    @app.route("/")
    def index():
        """Public Home Page with search, filters, dashboard summary cards, and alerts."""
        db_path = app.config["DATABASE_PATH"]
        auto_expire_alerts(db_path)

        # Query parameters for search & filters
        search_query = request.args.get("q", "").strip()
        route_query = request.args.get("route", "").strip()
        area_query = request.args.get("area", "").strip()
        category_query = request.args.get("category", "").strip()
        reason_query = request.args.get("reason", "").strip()
        status_query = request.args.get("status", "").strip()

        # Dynamic counts calculated from the database
        counts = get_dashboard_counts(db_path)

        # Retrieve filtered alerts
        alerts = get_alerts(
            search=search_query,
            route_number=route_query,
            area=area_query,
            category=category_query,
            reason=reason_query,
            status=status_query,
            db_path=db_path
        )

        # Check total alerts in DB to distinguish empty DB from empty search results
        total_in_db = len(get_alerts(db_path=db_path))

        return render_template(
            "index.html",
            alerts=alerts,
            counts=counts,
            total_in_db=total_in_db,
            search_query=search_query,
            route_query=route_query,
            area_query=area_query,
            selected_category=category_query,
            selected_reason=reason_query,
            selected_status=status_query
        )

    # ---------------------------------------------------------
    # Admin Authentication Routes
    # ---------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Administrator login page."""
        if "admin_id" in session:
            flash("You are already logged in as administrator.", "info")
            return redirect(url_for("admin_dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                flash("Please enter both username and password.", "danger")
                return render_template("login.html", username=username), 400

            db_path = app.config["DATABASE_PATH"]
            admin = get_admin_by_username(username, db_path)

            if admin and check_password_hash(admin["password_hash"], password):
                session["admin_id"] = admin["id"]
                session["admin_username"] = admin["username"]
                flash(f"Welcome back, {admin['username']}! Logged in successfully.", "success")
                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                return redirect(url_for("admin_dashboard"))
            else:
                flash("Invalid administrator username or password.", "danger")
                return render_template("login.html", username=username), 401

        return render_template("login.html")

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        """Administrator logout."""
        session.pop("admin_id", None)
        session.pop("admin_username", None)
        flash("You have been logged out successfully.", "info")
        return redirect(url_for("index"))

    # ---------------------------------------------------------
    # Administrator Dashboard & Management Routes
    # ---------------------------------------------------------

    @app.route("/admin")
    @app.route("/admin/dashboard")
    @login_required
    def admin_dashboard():
        """Administrator Dashboard: displays all alerts with administrative actions."""
        db_path = app.config["DATABASE_PATH"]
        auto_expire_alerts(db_path)

        search_query = request.args.get("q", "").strip()
        status_filter = request.args.get("status", "").strip()
        category_filter = request.args.get("category", "").strip()

        counts = get_dashboard_counts(db_path)
        alerts = get_alerts(
            search=search_query,
            category=category_filter,
            status=status_filter,
            db_path=db_path
        )

        return render_template(
            "admin_dashboard.html",
            alerts=alerts,
            counts=counts,
            search_query=search_query,
            status_filter=status_filter,
            category_filter=category_filter
        )

    @app.route("/admin/alerts/new", methods=["GET", "POST"])
    @login_required
    def add_alert():
        """Create a new bus alert."""
        db_path = app.config["DATABASE_PATH"]

        if request.method == "POST":
            # Extract and sanitize inputs
            title = request.form.get("title", "").strip()
            affected_area = request.form.get("affected_area", "").strip()
            route_number = request.form.get("route_number", "").strip() or None
            bus_stop = request.form.get("bus_stop", "").strip() or None
            category = request.form.get("category", "").strip()
            reason = request.form.get("reason", "").strip()
            description = request.form.get("description", "").strip()
            raw_delay = request.form.get("estimated_delay_minutes", "").strip()
            alternative_route = request.form.get("alternative_route", "").strip() or None
            source_name = request.form.get("source_name", "").strip() or None
            source_url = request.form.get("source_url", "").strip() or None
            verification_status = request.form.get("verification_status", "Unverified").strip()
            status = request.form.get("status", "Active").strip()
            raw_expires_at = request.form.get("expires_at", "").strip() or None

            errors = []

            # Validation
            if not title:
                errors.append("Alert title is required.")
            elif len(title) > 150:
                errors.append("Alert title cannot exceed 150 characters.")

            if not affected_area:
                errors.append("Affected area is required.")
            elif len(affected_area) > 100:
                errors.append("Affected area cannot exceed 100 characters.")

            if route_number and len(route_number) > 30:
                errors.append("Route number cannot exceed 30 characters.")

            if bus_stop and len(bus_stop) > 100:
                errors.append("Bus stop cannot exceed 100 characters.")

            if category not in CATEGORIES:
                errors.append(f"Invalid category selected. Must be one of: {', '.join(CATEGORIES)}.")

            if reason not in REASONS:
                errors.append(f"Invalid disruption reason selected. Must be one of: {', '.join(REASONS)}.")

            if not description:
                errors.append("Description is required.")
            elif len(description) > 1000:
                errors.append("Description cannot exceed 1000 characters.")

            if status not in STATUSES:
                errors.append(f"Invalid status. Must be one of: {', '.join(STATUSES)}.")

            if verification_status not in VERIFICATION_STATUSES:
                errors.append(f"Invalid verification status. Must be one of: {', '.join(VERIFICATION_STATUSES)}.")

            # Validate estimated delay
            estimated_delay_minutes = None
            if raw_delay:
                try:
                    estimated_delay_minutes = int(raw_delay)
                    if estimated_delay_minutes < 0:
                        errors.append("Estimated delay cannot be negative.")
                except ValueError:
                    errors.append("Estimated delay must be a valid whole number in minutes.")

            # Validate source URL
            if source_url and not is_valid_url(source_url):
                errors.append("Source reference URL must be a valid web address starting with http:// or https://.")

            # Validate expiration timestamp
            expires_at = None
            if raw_expires_at:
                try:
                    # Accepts HTML datetime-local format YYYY-MM-DDTHH:MM
                    dt = datetime.fromisoformat(raw_expires_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=KOLKATA_TZ)
                    expires_at = dt.isoformat()
                except ValueError:
                    errors.append("Invalid expiration date/time format.")

            if errors:
                for err in errors:
                    flash(err, "danger")
                return render_template(
                    "add_alert.html",
                    form_data=request.form
                ), 400

            # Insert alert into SQLite
            try:
                alert_id = create_alert(
                    title=title,
                    affected_area=affected_area,
                    category=category,
                    reason=reason,
                    description=description,
                    route_number=route_number,
                    bus_stop=bus_stop,
                    estimated_delay_minutes=estimated_delay_minutes,
                    alternative_route=alternative_route,
                    source_name=source_name,
                    source_url=source_url,
                    verification_status=verification_status,
                    status=status,
                    expires_at=expires_at,
                    db_path=db_path
                )
                flash(f"Bus alert #{alert_id} ('{title}') added successfully.", "success")
                return redirect(url_for("admin_dashboard"))
            except Exception as e:
                flash(f"Database error while saving alert: {e}", "danger")
                return render_template("add_alert.html", form_data=request.form), 500

        return render_template("add_alert.html", form_data={})

    @app.route("/admin/alerts/<int:alert_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_alert(alert_id: int):
        """Edit an existing bus alert."""
        db_path = app.config["DATABASE_PATH"]
        alert = get_alert_by_id(alert_id, db_path)
        if not alert:
            flash(f"Alert #{alert_id} not found.", "danger")
            return redirect(url_for("admin_dashboard")), 404

        if request.method == "POST":
            # Extract and sanitize inputs
            title = request.form.get("title", "").strip()
            affected_area = request.form.get("affected_area", "").strip()
            route_number = request.form.get("route_number", "").strip() or None
            bus_stop = request.form.get("bus_stop", "").strip() or None
            category = request.form.get("category", "").strip()
            reason = request.form.get("reason", "").strip()
            description = request.form.get("description", "").strip()
            raw_delay = request.form.get("estimated_delay_minutes", "").strip()
            alternative_route = request.form.get("alternative_route", "").strip() or None
            source_name = request.form.get("source_name", "").strip() or None
            source_url = request.form.get("source_url", "").strip() or None
            verification_status = request.form.get("verification_status", "Unverified").strip()
            status = request.form.get("status", "Active").strip()
            raw_expires_at = request.form.get("expires_at", "").strip() or None

            errors = []

            # Validation
            if not title:
                errors.append("Alert title is required.")
            elif len(title) > 150:
                errors.append("Alert title cannot exceed 150 characters.")

            if not affected_area:
                errors.append("Affected area is required.")
            elif len(affected_area) > 100:
                errors.append("Affected area cannot exceed 100 characters.")

            if route_number and len(route_number) > 30:
                errors.append("Route number cannot exceed 30 characters.")

            if bus_stop and len(bus_stop) > 100:
                errors.append("Bus stop cannot exceed 100 characters.")

            if category not in CATEGORIES:
                errors.append(f"Invalid category. Must be one of: {', '.join(CATEGORIES)}.")

            if reason not in REASONS:
                errors.append(f"Invalid disruption reason. Must be one of: {', '.join(REASONS)}.")

            if not description:
                errors.append("Description is required.")
            elif len(description) > 1000:
                errors.append("Description cannot exceed 1000 characters.")

            if status not in STATUSES:
                errors.append(f"Invalid status. Must be one of: {', '.join(STATUSES)}.")

            if verification_status not in VERIFICATION_STATUSES:
                errors.append(f"Invalid verification status. Must be one of: {', '.join(VERIFICATION_STATUSES)}.")

            # Validate estimated delay
            estimated_delay_minutes = None
            if raw_delay:
                try:
                    estimated_delay_minutes = int(raw_delay)
                    if estimated_delay_minutes < 0:
                        errors.append("Estimated delay cannot be negative.")
                except ValueError:
                    errors.append("Estimated delay must be a valid whole number in minutes.")

            # Validate source URL
            if source_url and not is_valid_url(source_url):
                errors.append("Source reference URL must be a valid web address starting with http:// or https://.")

            # Validate expiration timestamp
            expires_at = None
            if raw_expires_at:
                try:
                    dt = datetime.fromisoformat(raw_expires_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=KOLKATA_TZ)
                    expires_at = dt.isoformat()
                except ValueError:
                    errors.append("Invalid expiration date/time format.")

            if errors:
                for err in errors:
                    flash(err, "danger")
                return render_template(
                    "edit_alert.html",
                    alert=alert,
                    form_data=request.form
                ), 400

            # Update alert in SQLite
            try:
                updated = update_alert(
                    alert_id=alert_id,
                    title=title,
                    affected_area=affected_area,
                    category=category,
                    reason=reason,
                    description=description,
                    route_number=route_number,
                    bus_stop=bus_stop,
                    estimated_delay_minutes=estimated_delay_minutes,
                    alternative_route=alternative_route,
                    source_name=source_name,
                    source_url=source_url,
                    verification_status=verification_status,
                    status=status,
                    expires_at=expires_at,
                    db_path=db_path
                )
                if updated:
                    flash(f"Alert #{alert_id} updated successfully.", "success")
                else:
                    flash(f"Could not update alert #{alert_id}.", "warning")
                return redirect(url_for("admin_dashboard"))
            except Exception as e:
                flash(f"Database error while updating alert: {e}", "danger")
                return render_template("edit_alert.html", alert=alert, form_data=request.form), 500

        return render_template("edit_alert.html", alert=alert, form_data=alert)

    @app.route("/admin/alerts/<int:alert_id>/resolve", methods=["POST"])
    @login_required
    def resolve_alert_action(alert_id: int):
        """Quick action: Mark an alert as Resolved."""
        db_path = app.config["DATABASE_PATH"]
        alert = get_alert_by_id(alert_id, db_path)
        if not alert:
            flash(f"Alert #{alert_id} not found.", "danger")
            return redirect(url_for("admin_dashboard")), 404

        success = set_alert_status(alert_id, "Resolved", db_path)
        if success:
            flash(f"Alert #{alert_id} has been marked as Resolved.", "success")
        else:
            flash(f"Failed to resolve alert #{alert_id}.", "danger")

        # Redirect back to referring page if available
        next_url = request.referrer or url_for("admin_dashboard")
        return redirect(next_url)

    @app.route("/admin/alerts/<int:alert_id>/expire", methods=["POST"])
    @login_required
    def expire_alert_action(alert_id: int):
        """Quick action: Mark an alert as Expired."""
        db_path = app.config["DATABASE_PATH"]
        alert = get_alert_by_id(alert_id, db_path)
        if not alert:
            flash(f"Alert #{alert_id} not found.", "danger")
            return redirect(url_for("admin_dashboard")), 404

        success = set_alert_status(alert_id, "Expired", db_path)
        if success:
            flash(f"Alert #{alert_id} has been marked as Expired.", "info")
        else:
            flash(f"Failed to expire alert #{alert_id}.", "danger")

        next_url = request.referrer or url_for("admin_dashboard")
        return redirect(next_url)

    @app.route("/admin/alerts/<int:alert_id>/verify", methods=["POST"])
    @login_required
    def toggle_verify_action(alert_id: int):
        """Toggle or set verification status for an alert."""
        db_path = app.config["DATABASE_PATH"]
        alert = get_alert_by_id(alert_id, db_path)
        if not alert:
            flash(f"Alert #{alert_id} not found.", "danger")
            return redirect(url_for("admin_dashboard")), 404

        target_status = request.form.get("verification_status")
        if not target_status or target_status not in VERIFICATION_STATUSES:
            target_status = "Verified" if alert["verification_status"] == "Unverified" else "Unverified"

        success = set_alert_verification(alert_id, target_status, db_path)
        if success:
            flash(f"Alert #{alert_id} verification set to '{target_status}'.", "success")
        else:
            flash(f"Failed to update verification for alert #{alert_id}.", "danger")

        next_url = request.referrer or url_for("admin_dashboard")
        return redirect(next_url)

    @app.route("/admin/alerts/<int:alert_id>/delete", methods=["POST"])
    @login_required
    def delete_alert_action(alert_id: int):
        """Delete an alert."""
        db_path = app.config["DATABASE_PATH"]
        alert = get_alert_by_id(alert_id, db_path)
        if not alert:
            flash(f"Alert #{alert_id} not found.", "danger")
            return redirect(url_for("admin_dashboard")), 404

        success = delete_alert(alert_id, db_path)
        if success:
            flash(f"Alert #{alert_id} deleted successfully.", "success")
        else:
            flash(f"Failed to delete alert #{alert_id}.", "danger")

        return redirect(url_for("admin_dashboard"))

    # ---------------------------------------------------------
    # Error Handlers
    # ---------------------------------------------------------

    @app.errorhandler(400)
    def bad_request(error):
        message = getattr(error, "description", "Bad Request")
        return render_template("404.html", error_title="400 - Bad Request", error_message=message), 400

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "404.html",
            error_title="404 - Page Not Found",
            error_message="The bus alert or page you are looking for does not exist or has been removed."
        ), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template(
            "404.html",
            error_title="500 - Server Error",
            error_message="An unexpected server error occurred. Please try again later."
        ), 500

    # ---------------------------------------------------------
    # CLI Commands
    # ---------------------------------------------------------

    @app.cli.command("init-db")
    def init_db_command():
        """Initialize SQLite database tables and indexes."""
        init_db(app.config["DATABASE_PATH"])
        print(f"Database initialized at {app.config['DATABASE_PATH']}.")

    @app.cli.command("create-admin")
    def create_admin_command():
        """CLI tool to create a new administrator account safely."""
        import getpass
        username = input("Enter admin username: ").strip()
        password = getpass.getpass("Enter admin password (min 6 chars): ")
        confirm_password = getpass.getpass("Confirm admin password: ")

        if password != confirm_password:
            print("Error: Passwords do not match.")
            return

        try:
            admin_id = create_admin_user(username, password, app.config["DATABASE_PATH"])
            print(f"Success: Administrator '{username}' created with ID {admin_id}.")
        except Exception as e:
            print(f"Error: {e}")

    return app


# Default app instance for Flask CLI and WSGI servers
app = create_app()

if __name__ == "__main__":
    # Run development server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
