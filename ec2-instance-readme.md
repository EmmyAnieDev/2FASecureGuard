# 2FASecureGuard Deployment Guide

This guide provides step-by-step instructions for deploying the 2FASecureGuard FastAPI application on an Amazon Linux EC2 instance using Nginx as a reverse proxy.

## Prerequisites

- An AWS EC2 instance (Amazon Linux) with public IP: your-server-ip
- SSH access to your EC2 instance
- GitHub repository: https://github.com/EmmyAnieDev/2FASecureGuard.git
- Domain name (optional)

## Deployment Steps

### 1. Connect to your EC2 instance

```bash
ssh ec2-user@your-server-ip
```

### 2. Update and install required packages

```bash
# Update package lists
sudo yum update -y

# Install required packages
sudo yum install -y python3-pip git
sudo amazon-linux-extras install -y nginx1
```

### 3. Clone the GitHub repository

```bash
# Navigate to home directory
cd ~

# Clone the repository
git clone https://github.com/EmmyAnieDev/2FASecureGuard.git

# Navigate to the project directory
cd 2FASecureGuard
```

### 4. Set up Python virtual environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Create a systemd service file for your application

```bash
sudo nano /etc/systemd/system/2fasecureguard.service
```

Add the following content:

```
[Unit]
Description=2FASecureGuard FastAPI application
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/2FASecureGuard
ExecStart=/home/ec2-user/2FASecureGuard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable 2fasecureguard
sudo systemctl start 2fasecureguard
```

Check the status of the service:

```bash
sudo systemctl status 2fasecureguard
```

### 6. Install and Configure Nginx

Install and set up Nginx as a reverse proxy:

```bash
    # Install Nginx
    sudo yum install nginx -y
    
    # Start Nginx
    sudo systemctl start nginx
    
    # Enable Nginx to start on boot
    sudo systemctl enable nginx
    
    # Check if Nginx is running
    sudo systemctl status nginx
```

### 7. Configure Nginx as a reverse proxy

```bash
sudo nano /etc/nginx/conf.d/2fasecureguard.conf
```

Add the following configuration:

```
server {
    listen 80;
    server_name your-server-ip; # Replace with your domain name if available

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Check the Nginx configuration syntax:

```bash
sudo nginx -t
```

If the syntax is valid, restart Nginx:

```bash
sudo systemctl restart nginx
```

### 9. Configure firewall rules (if applicable)

Make sure your EC2 security group allows traffic on ports 22 (SSH), 80 (HTTP), and 443 (HTTPS).

1. Go to the AWS Console
2. Navigate to EC2 > Security Groups
3. Select the security group associated with your instance
4. Add inbound rules for ports 80 and 443 (if not already present)

## Verification

Access your application through your browser:

```
http:your-server-ip
```

This should return:
```
{"message: server is active"}
```

## Troubleshooting

### Check application logs

```bash
sudo journalctl -u 2fasecureguard
```

### Check Nginx logs

```bash
sudo cat /var/log/nginx/error.log
sudo cat /var/log/nginx/access.log
```

### Check application status

```bash
sudo systemctl status 2fasecureguard
```

### Check Nginx status

```bash
sudo systemctl status nginx
```

## Maintenance

### Updating the application

```bash
cd ~/2FASecureGuard
git pull
source venv/bin/activate
pip install -r requirements.txt  # If requirements have changed
sudo systemctl restart 2fasecureguard
```

### Nginx configuration changes

After making changes to Nginx configuration:

```bash
sudo nginx -t  # Check syntax
sudo systemctl restart nginx  # Apply changes
```

## Additional Security Considerations

1. Consider setting up SSL/TLS with Let's Encrypt
2. Implement rate limiting in Nginx
3. Review EC2 security groups regularly
4. Keep software updated regularly with `sudo yum update`

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [AWS EC2 Documentation](https://docs.aws.amazon.com/ec2/)