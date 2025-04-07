# Use Python base image
FROM python:3.11

# Set working directory in container
WORKDIR /app

# Install Flask directly
RUN pip install flask
RUN pip install flask-jwt-extended

RUN apt-get update
RUN apt install -y iputils-ping

# Copy the entire project
COPY . .

# Expose port 5000 for Flask
EXPOSE 5001

# Run Flask app
CMD ["python", "app.py"]
