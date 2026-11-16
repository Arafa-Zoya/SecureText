
from flask import Flask, jsonify, send_from_directory

from backend.routes.encryption import encryption_bp

from backend.routes.files import files_bp

def create_app():
    app = Flask(
        __name__,
        static_folder="frontend",
        static_url_path="/static"
    )

    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

    app.register_blueprint(encryption_bp, url_prefix="/api")
    app.register_blueprint(files_bp, url_prefix="/api")

    @app.route("/")
    def home():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "online",
            "application": "SecureText",
            "message": "SecureText API is running."
        })

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
