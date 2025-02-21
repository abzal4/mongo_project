from fastapi import FastAPI, HTTPException, Depends, Query, status
import requests
from pymongo import MongoClient
from bson import ObjectId
from pydantic import BaseModel
from typing import List, Optional
import logging
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Books API",
        version="1.0.0",
        description="API for managing books and reviews",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = MongoClient("mongodb://localhost:27017")
db = client.mongo_project
books_collection = db.books  
users_collection = db.users  
reviews_collection = db.reviews

books_collection.create_index("user")
reviews_collection.create_index("book_id")

app = FastAPI()
app.openapi = custom_openapi

# encryption of passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# models
class Book(BaseModel):
    google_book_id: str
    title: str
    authors: List[str]
    published_date: Optional[str] = None
    description: str
    pdf_link: Optional[str] = None
    buy_link: Optional[str] = None
    priceKZT: Optional[float] = None
    user: str 

class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = False

class Review(BaseModel):
    book_id: str
    user: str
    rating: int
    comment: str
    created_at: datetime = datetime.utcnow()

class UserInDB(User):
    hashed_password: str
    is_admin: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# functions for authentication
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    user_data = users_collection.find_one({"username": username})
    if user_data:
        return UserInDB(**user_data)
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    if not getattr(current_user, "is_admin", False):  
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# for books
def analyze_book(book, username: str):
    volume_info = book.get("volumeInfo", {})
    sale_info = book.get("saleInfo", {})
    access_info = book.get("accessInfo", {})
    pdf_link = "None"
    price = 0
    if sale_info.get("saleability")=={"FREE"}:
        pdf_link = access_info["webReaderLink"]
    elif sale_info.get("saleability")==("FOR_SALE"):
        price = sale_info.get("listPrice", {}).get("amount")
    buy_link = sale_info.get("buyLink")
    google_book = Book(
        google_book_id = book.get('id'),
        title = volume_info.get('title', 'Unknown'),
        authors = volume_info.get('authors', ['Unknown']),
        published_date = volume_info.get('publishedDate','Unknown'),
        description = volume_info.get('description','Unknown'),
        pdf_link=pdf_link,
        buy_link=buy_link,
        priceKZT = price,
        user=username
    )
    return google_book


# registration 
@app.post("/register", response_model=dict)
async def register(username: str, email: str, password: str, full_name: str = ""):
    if get_user(username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = get_password_hash(password)
    new_user = {
        "username": username,
        "email": email,
        "full_name": full_name,
        "hashed_password": hashed_password,
        "disabled": False,
        "is_admin": False
    }
    users_collection.insert_one(new_user)
    return {"message": "User registered successfully"}

# login and getting token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

# current user
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# -----------------------REVIEWS ----------------------------------------------------------------------------------------
@app.post("/reviews/", response_model=dict, )
def create_review(review: Review, current_user: User = Depends(get_current_active_user)):
    new_review = review.dict()
    new_review["user_id"] = current_user.username
    result = reviews_collection.insert_one(new_review)
    return {"id": str(result.inserted_id)}

@app.get("/reviews/{book_id}", response_model=List[dict])
def get_reviews(book_id: str, current_user: User = Depends(get_current_active_user)):
    reviews = list(reviews_collection.find({"book_id": book_id}))
    for review in reviews:
        review["id"] = str(review["_id"])
        del review["_id"]
    return reviews

@app.put("/reviews/{review_id}", response_model=dict)
def update_review(review_id: str, review: Review, current_user: User = Depends(get_current_active_user)):
    result = reviews_collection.update_one({"_id": ObjectId(review_id)}, {"$set": review.dict()})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Review not found")
    return {"message": "Review updated successfully"}

@app.delete("/reviews/{review_id}", response_model=dict)
def delete_review(review_id: str, current_user: User = Depends(get_current_admin_user)):
    result = reviews_collection.delete_one({"_id": ObjectId(review_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Review not found")
    return {"message": "Review deleted successfully"}

@app.get("/books/", response_model=List[dict])
async def get_books_with_reviews(current_user: User = Depends(get_current_admin_user)):
    books_with_reviews = books_collection.aggregate([
        {
            "$lookup": {
                "from": "reviews", 
                "localField": "google_book_id", 
                "foreignField": "book_id",  
                "as": "reviews" 
            }},
            {
            "$match": {
                "reviews": {"$ne": []}  # Only return books that have reviews
            }
            },
            {   
                "$project": {
                    "_id": 1,  # Remove _id
                    "title": 1,  # Keep book title
                    "reviews": 1  # Keep reviews
                    }}
    ])
    books = []
    for book in books_with_reviews:
        book["_id"] = str(book["_id"])  
        for review in book["reviews"]:
            review["_id"] = str(review["_id"])  
        books.append(book)

    return books

# -----------------------BOOKS----------------------------------------------------------------------------------------
@app.post("/books/create", response_model=dict)
async def create_books(book: Book, current_user: User = Depends(get_current_active_user)):
    new_book = book.dict()
    result = books_collection.insert_one(new_book)
    return {"id": str(result.inserted_id)}

@app.get("/books/get", response_model=List[dict])
async def get_books(current_user: User = Depends(get_current_admin_user)):
    books = list(books_collection.find())
    for book in books:
        book["id"] = str(book["_id"])
        del book["_id"]
    return books

@app.get("/books/my", response_model=List[dict])
async def get_user_books(current_user: User = Depends(get_current_active_user)):
    books = list(books_collection.find({"user": current_user.username}))
    for book in books:
        book["id"] = str(book["_id"])
        del book["_id"]
    return books

@app.get("/books/googleapi")
async def get_google_books(query: str = Query(..., description="Book title"), current_user: User = Depends(get_current_active_user)):
    API_KEY="AIzaSyBGh65pb-jiy5sUqrj9l3cUpbU-hWX_rVo"
    url = f"https://www.googleapis.com/books/v1/volumes?q={query}&key={API_KEY}"
    response = requests.get(url)
    if response.status_code != 200:
        logging.error(f"Google Books API error: {response.status_code}")
        raise HTTPException(status_code=500, detail="Error with Google Books API")
    result = response.json()
    books = result.get("items", [])
    google_books=[]
    for book in books:
        google_books.append(analyze_book(book, current_user.username))
    return google_books
    
@app.post("/books/add_google_book", response_model=dict)
async def add_google_book(book_id: str = Query(..., description="Google book id"), current_user: User = Depends(get_current_active_user)):
    url = f"https://www.googleapis.com/books/v1/volumes/{book_id}"
    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error fetching book from Google API")
    result = response.json()
    new_book = analyze_book(result, current_user.username)
    book_data = new_book.dict()
    book_data["user"] = current_user.username
    result = books_collection.insert_one(new_book.dict())
    return {"id": str(result.inserted_id)}

@app.put("/books/{book_id}", response_model=dict)
async def update_book(book_id: str, book: Book, current_user: User = Depends(get_current_active_user)):
    result = books_collection.update_one({"_id": ObjectId(book_id)}, {"$set": book.dict()})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"message": "Book updated successfully"}

@app.delete("/books/deleteall", response_model=dict, )
def delete_all_books(current_user: User = Depends(get_current_admin_user)):
    result = books_collection.delete_many({})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="No books in database")
    return {"message": "Books deleted successfully"}

@app.delete("/books/{book_id}", response_model=dict)
async def delete_book(book_id: str, current_user: User = Depends(get_current_active_user)):
    result = books_collection.delete_one({"_id": ObjectId(book_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"message": "Book deleted successfully"}

