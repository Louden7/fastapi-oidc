from fastapi import FastAPI, HTTPException
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
import os

app = FastAPI()

SECRET_KEY = os.getenv("SESSION_SECRET", "your_very_secret_key")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# GitLab OIDC Configuration
GITLAB_OIDC_URL = "https://gitlab.com/.well-known/openid-configuration"
GITLAB_USERINFO_URL = "https://gitlab.com/oauth/userinfo"
GITLAB_LOGOUT_URL = "https://gitlab.com/users/sign_out"
CLIENT_ID = ""
CLIENT_SECRET = ""
REDIRECT_URI = "http://localhost:8000/auth/callback"

# Setup OAuth
oauth = OAuth()
oauth.register(
    name="gitlab",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=GITLAB_OIDC_URL,
    client_kwargs={"scope": "openid email profile"},
)


@app.get("/login")
async def login(request: Request):
    return await oauth.gitlab.authorize_redirect(request, REDIRECT_URI)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    token = await oauth.gitlab.authorize_access_token(request)

    if "access_token" not in token:
        return {"error": "Authentication failed", "details": token}

    access_token = token["access_token"]

    # ✅ Fetch user info manually
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            GITLAB_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        )

    if user_info_response.status_code != 200:
        return {
            "error": "Failed to fetch user info",
            "details": user_info_response.text,
        }

    user_info = user_info_response.json()
    request.session["user"] = user_info  # Store in session

    return {"access_token": access_token, "user": user_info}


@app.get("/")
async def home():
    return {"message": "Welcome to FastAPI with GitLab OIDC"}


@app.get("/logout")
async def logout(request: Request):
    """
    Clears session and redirects the user to GitLab's logout page.
    """
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/user")
async def get_user(request: Request):
    user = request.session.get("user")
    if not user:
        return {"error": "Not authenticated"}
    return {"user": user}


@app.get("/me")
async def get_me(request: Request):
    """
    Protected endpoint that returns the authenticated user's info.
    """
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {"user": user}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
