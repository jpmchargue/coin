import uvicorn
SERVER_PORT = 5000

print("Starting server...")
uvicorn.run("server:app", port=SERVER_PORT, log_level="info")