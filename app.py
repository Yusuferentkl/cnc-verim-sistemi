import os
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

app = Flask(__name__)

app.secret_key = "secret123"

db_url = os.environ.get("DATABASE_URL")

if db_url:
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    os.makedirs("instance", exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///instance/verim.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

OPERATIONS = ["1. Operasyon", "2. Operasyon", "Yargı", "Ayar"]

CNC_LIST = [
"CNC1","CNC2","CNC3","CNC4",
"CNC5","CNC6","CNC7","CNC8"
]


class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True,nullable=False)
    password_hash=db.Column(db.String(200),nullable=False)
    role=db.Column(db.String(20),nullable=False)


class Part(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    part_code=db.Column(db.String(200),nullable=False)
    operation=db.Column(db.String(20),nullable=False)
    setup_time=db.Column(db.Integer,nullable=False)


class Work(db.Model):
    id=db.Column(db.Integer,primary_key=True)

    operator=db.Column(db.String(50))
    cnc=db.Column(db.String(20))

    part_code=db.Column(db.String(200))
    operation=db.Column(db.String(20))

    start_time=db.Column(db.String(10))
    end_time=db.Column(db.String(10))

    process_time_sec=db.Column(db.Integer)
    quantity=db.Column(db.Integer)

    downtime_reason=db.Column(db.String(200))
    downtime_seconds=db.Column(db.Integer)

    efficiency=db.Column(db.Float)

    date=db.Column(db.DateTime,default=datetime.now)


class BreakTime(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    start_time=db.Column(db.String(5))
    end_time=db.Column(db.String(5))


def parse_time(t):
    return datetime.strptime(t,"%H:%M")


def calculate_net_seconds(start,end):

    start=parse_time(start)
    end=parse_time(end)

    total=(end-start).total_seconds()

    breaks=BreakTime.query.all()

    for b in breaks:

        bs=parse_time(b.start_time)
        be=parse_time(b.end_time)

        overlap_start=max(start,bs)
        overlap_end=min(end,be)

        if overlap_start<overlap_end:
            total-= (overlap_end-overlap_start).total_seconds()

    return max(total,0)


def calculate_efficiency(start,end,process,setup,qty,downtime):

    net=calculate_net_seconds(start,end)-downtime

    if net<=0:
        return 0

    standard=process+setup

    if standard<=0:
        return 0

    target=net/standard

    if target<=0:
        return 0

    return round((qty/target)*100,2)


@app.route("/")
def home():
    return redirect("/login")


@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        username=request.form["username"]
        password=request.form["password"]

        user=User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash,password):

            session["user"]=user.username
            session["role"]=user.role

            if user.role=="admin":
                return redirect("/admin")

            return redirect("/operator")

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()
    return redirect("/login")


@app.route("/operator",methods=["GET","POST"])
def operator():

    if session.get("role")!="operator":
        return redirect("/login")

    parts=Part.query.with_entities(Part.part_code).distinct().all()

    part_codes=[p.part_code for p in parts]

    if request.method=="POST":

        cnc=request.form["cnc"]
        part=request.form["part_code"]
        op=request.form["operation"]

        start=request.form["start_time"]
        end=request.form["end_time"]

        qty=int(request.form["quantity"])

        pmin=int(request.form["process_min"])
        psec=int(request.form["process_sec_part"])

        process=pmin*60+psec

        dmin=int(request.form["downtime_min"])
        dsec=int(request.form["downtime_sec_part"])

        downtime=dmin*60+dsec

        reason=request.form["downtime_reason"]

        if op=="Ayar":

            eff=0

        else:

            part_row=Part.query.filter_by(
            part_code=part,
            operation=op
            ).first()

            if not part_row:

                return render_template(
                "operator.html",
                part_codes=part_codes,
                operations=OPERATIONS,
                cnc_list=CNC_LIST,
                message="Parça tanımlı değil"
                )

            eff=calculate_efficiency(
            start,end,
            process,
            part_row.setup_time,
            qty,
            downtime
            )

        work=Work(
        operator=session["user"],
        cnc=cnc,
        part_code=part,
        operation=op,
        start_time=start,
        end_time=end,
        process_time_sec=process,
        quantity=qty,
        downtime_reason=reason,
        downtime_seconds=downtime,
        efficiency=eff
        )

        db.session.add(work)
        db.session.commit()

    works=Work.query.filter_by(
    operator=session["user"]
    ).order_by(Work.date.desc()).limit(100).all()

    return render_template(
    "operator.html",
    part_codes=part_codes,
    operations=OPERATIONS,
    cnc_list=CNC_LIST,
    works=works
    )


@app.route("/admin")
def admin():

    if session.get("role")!="admin":
        return redirect("/login")

    works=Work.query.order_by(Work.date.desc()).limit(200).all()

    week=datetime.now()-timedelta(days=7)

    rank=db.session.query(
    Work.operator,
    func.avg(Work.efficiency)
    ).filter(
    Work.date>=week,
    Work.operation!="Ayar"
    ).group_by(Work.operator).all()

    breaks=BreakTime.query.all()

    return render_template(
    "admin.html",
    works=works,
    weekly_rank=rank,
    breaks=breaks
    )


def init_db():

    db.create_all()

    if not User.query.filter_by(username="admin").first():

        admin=User(
        username="admin",
        password_hash=generate_password_hash("admin123"),
        role="admin"
        )

        db.session.add(admin)
        db.session.commit()


with app.app_context():
    init_db()


if __name__=="__main__":
    app.run(debug=True)