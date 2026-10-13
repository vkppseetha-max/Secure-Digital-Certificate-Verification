from flask import Flask, render_template, request
from datetime import datetime
import hashlib
import uuid

from blockchain import blockchain
from database import (
    create_tables,
    add_certificate,
    get_certificate
)

app = Flask(__name__)

create_tables()


@app.route("/")
def home():
    return render_template("result.html")


@app.route("/issue", methods=["GET", "POST"])
def issue():

    if request.method == "POST":

        name = request.form["name"]
        course = request.form["course"]

        certificate_id = "CERT-" + uuid.uuid4().hex[:8].upper()
        issue_date = datetime.now().strftime("%Y-%m-%d")

        text = certificate_id + name + course + issue_date

        certificate_hash = hashlib.sha256(
            text.encode()
        ).hexdigest()

        data = {
            "certificate_id": certificate_id,
            "student_name": name,
            "course": course,
            "issue_date": issue_date,
            "certificate_hash": certificate_hash
        }

        block = blockchain.add_block(data)

        add_certificate({
            "certificate_id": certificate_id,
            "student_name": name,
            "course": course,
            "issue_date": issue_date,
            "certificate_hash": certificate_hash,
            "blockchain_hash": block.hash
        })

        return render_template(
            "result.html",
            certificate=data,
            blockchain_hash=block.hash
        )

    return render_template("issue.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        certificate_id = request.form["certificate_id"]

        certificate = get_certificate(certificate_id)

        if certificate:

            block = blockchain.find_certificate(certificate_id)

            if block and blockchain.verify_chain():
                result = "VALID"
            else:
                result = "INVALID"

        else:
            result = "INVALID"

    return render_template(
        "verify.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)
