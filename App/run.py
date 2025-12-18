from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=True for demo; in production use a proper WSGI server
    app.run(debug=True, ssl_context="adhoc")
