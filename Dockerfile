# Use a lighter python image
FROM python:3.11-slim

WORKDIR /app

# Only install basic essentials if absolutely needed (usually not for simple python apps)
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Hugging Face uses port 7860 by default
EXPOSE 7860

# Ensure the start script is executable
RUN chmod +x start.sh

# Start the application
CMD ["./start.sh"]
