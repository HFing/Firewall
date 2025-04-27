class Config:
    SECRET_KEY = 'supersecret'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://admin:firewall123@rds-firewall-saas.cdaks2iyajd3.ap-southeast-1.rds.amazonaws.com:3306/firewall_saas'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
