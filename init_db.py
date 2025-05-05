from app import app, db

# Reset the database (⚠️ This will delete all existing data!)
with app.app_context():
    db.drop_all()
    db.create_all()
    print("Database dropped and recreated successfully!")
