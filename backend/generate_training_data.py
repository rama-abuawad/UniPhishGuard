import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "training_emails.csv"


LEGITIMATE_TEMPLATES = [
    ("Updated Tuition Fees - Academic Year {year}", "Dear Student, tuition fees for academic year {year} are available on the ADU website. Please check the tuition fees page and use the official online payment gateway."),
    ("Class schedule update", "Your class schedule for {semester} has been updated in the student portal. Please review your timetable before classes start."),
    ("Internship visit schedule reminder", "Dear Internship Students, please update your company supervisor contact details and visit dates in the internship form."),
    ("Library account notice", "This is a reminder that your library book is due on {date}. Please return or renew it through the university library portal."),
    ("Campus maintenance notice", "IT services will perform scheduled maintenance on {date}. Some university systems may be unavailable for a short time."),
    ("Scholarship application result", "Your scholarship application status is available in the student portal. Log in through the official university website."),
    ("Exam hall announcement", "Please check your exam hall and seat number in the student system before the exam date."),
    ("Finance payment confirmation", "Your tuition payment has been received by the finance office. Keep this email for your records."),
    ("ADU event invitation", "You are invited to attend the student success workshop on campus in {month}. Registration is available on the university website."),
    ("Password changed successfully", "Your university password was changed successfully. If this was not you, contact IT support through the official service desk."),
    ("Tuition payment deadline reminder", "Dear Student, this is a reminder that the tuition payment deadline is next week. Please use the official university portal."),
    ("Course registration confirmation", "Your course registration for {semester} has been completed. Please check the student portal for details."),
    ("Finance office receipt", "The finance office confirms that your payment receipt is available in the student portal."),
    ("Academic advising appointment", "Your academic advising appointment has been scheduled for {date}. Please attend on time or contact your advisor."),
    ("Student ID card collection", "Your student ID card is ready for collection from the registration office during working hours."),
    ("Blackboard course access", "Your Blackboard course access has been updated for {semester}."),
    ("IT support ticket update", "Your IT support ticket has been updated. Please check the service desk portal for the reply."),
    ("University WiFi maintenance", "The university WiFi network will be under maintenance on {date} from 10 PM to 11 PM."),
    ("Graduation ceremony registration", "Graduation ceremony registration is open. Please register through the official student portal."),
    ("Transport schedule update", "The campus bus schedule has been updated for {semester}."),
    ("Research survey invitation", "You are invited to complete a university research survey. Participation is optional."),
    ("Dean's list announcement", "The Dean's list for the previous semester has been published on the university website."),
    ("Lab safety training", "Students registered in lab courses must complete the lab safety training module before attending the lab."),
    ("Student housing notice", "Please review the housing office notice about room maintenance this weekend."),
    ("Career fair reminder", "The university career fair will take place next Wednesday in the main hall."),
    ("Moodle maintenance completed", "The Moodle maintenance has been completed and services are now available."),
    ("Payment plan approved", "Your tuition payment plan has been approved by the finance office."),
    ("Official transcript request", "Your official transcript request has been received and is being processed."),
    ("Course evaluation reminder", "Please complete the course evaluation form before the deadline."),
    ("Student portal notification", "A new notification is available in your student portal account."),
    ("Internship document approved", "Your internship document has been approved by the internship office."),
    ("Financial aid document missing", "The financial aid office needs one missing document. Upload it through the official portal."),
    ("Exam timetable published", "The final exam timetable has been published on the university website."),
    ("Lecture room changed", "The lecture room for your class has changed. Please check the updated location."),
    ("University policy update", "The university has updated the attendance policy. Please read it on the official website."),
    ("Workshop registration confirmation", "Your workshop registration is confirmed. The session will be held on campus."),
    ("Library workshop reminder", "This is a reminder for the library research skills workshop tomorrow."),
    ("Official finance announcement", "The finance department has published updated payment methods on the ADU website."),
    ("Tuition fee invoice available", "Your tuition fee invoice is available in the student portal for viewing."),
    ("Course withdrawal deadline", "The course withdrawal deadline is approaching. Please contact registration for support."),
]


PHISHING_TEMPLATES = [
    ("Urgent password verification required", "Your account will be suspended today. Click here to verify your password immediately."),
    ("Mailbox storage full", "Your email storage is full and incoming messages will be blocked. Login immediately to keep your account active."),
    ("Final warning account locked", "We detected unusual activity. Confirm your password now or your account will be locked."),
    ("Invoice payment overdue", "Open the attached invoice and make payment today to avoid legal action."),
    ("Security alert verify account", "Your account has been limited. Click the link below and verify your account details."),
    ("Prize claim request", "Congratulations, you have won a reward. Send your login details to claim it."),
    ("Microsoft password expires", "Your password expires in 2 hours. Click here to confirm your password and keep access."),
    ("Document shared with you", "Open the document and sign in with your email password to view the secure file."),
    ("Payroll update required", "Your salary payment is on hold. Update your bank account details immediately."),
    ("University grant approval", "You are approved for a grant. Pay the processing fee through this link today."),
    ("Confirm mailbox now", "Failure to confirm your mailbox will result in permanent email deletion."),
    ("Account verification notice", "Verify your account at the link below to prevent service interruption."),
    ("Student portal blocked", "Your student portal access has been blocked. Enter your username and password to restore it."),
    ("Fake tuition refund", "You are eligible for a tuition refund. Submit your card details to receive the payment."),
    ("Urgent dean message", "The dean requests urgent confirmation of your login details before midnight."),
    ("OneDrive file blocked", "A file was blocked for security reasons. Sign in with your password to release it."),
    ("Scholarship fee required", "Pay the approval fee today to activate your scholarship award."),
    ("Email quarantine release", "Several messages are held in quarantine. Login now to release them."),
    ("Fake IT support update", "IT support needs your password to complete the account upgrade."),
    ("Payment failed warning", "Your payment failed. Click this external link and enter your bank card information."),
    ("Urgent invoice attachment", "Please open invoice.pdf.exe and process the payment immediately."),
    ("Verify Duo account", "Your two factor account will expire. Verify your login at the attached link."),
    ("Office 365 reactivation", "Reactivate your Office 365 account by entering your password on this page."),
    ("Unusual login detected", "Unusual login detected from another country. Confirm your password to secure your account."),
    ("Final payment notice", "Final notice. Pay through this link within one hour or your account will be closed."),
    ("Fake registration cancellation", "Your course registration will be cancelled unless you verify your account now."),
    ("Shared exam document", "A confidential exam document was shared with you. Sign in using your email password."),
    ("Bank account confirmation", "Confirm your bank account details to continue receiving university payments."),
    ("Suspicious activity form", "Complete this security form with your password and recovery phone number."),
    ("Urgent helpdesk ticket", "Your helpdesk ticket requires password confirmation to stay open."),
    ("Fake Zoom recording", "A Zoom recording is ready. Login at this external page to view it."),
    ("Account cleanup required", "Inactive accounts will be removed today. Click here and login immediately."),
    ("Tuition discount claim", "Claim a tuition discount by paying a small processing fee today."),
    ("Fake library fine", "Your library fine must be paid through this link today to avoid suspension."),
    ("Email upgrade required", "Upgrade your mailbox now by entering your email address and password."),
    ("Fake HR document", "Open the secure HR document and authenticate with your university password."),
    ("Refund card update", "Update your card number and CVV to receive your university refund."),
    ("Urgent security survey", "Complete this mandatory security survey and include your login credentials."),
    ("External payment portal", "Use this external payment portal to avoid losing your student account."),
    ("Fake account migration", "Your account is moving to a new server. Provide your current password to migrate."),
]


VARIATIONS = [
    {"year": "2025-2026", "semester": "Fall 2025", "date": "Monday", "month": "September"},
    {"year": "2026-2027", "semester": "Spring 2026", "date": "Tuesday", "month": "October"},
    {"year": "2027-2028", "semester": "Summer 2026", "date": "Wednesday", "month": "November"},
    {"year": "2028-2029", "semester": "Fall 2026", "date": "Thursday", "month": "January"},
    {"year": "2029-2030", "semester": "Spring 2027", "date": "Friday", "month": "February"},
]


def build_rows(label: str, templates: list[tuple[str, str]], count: int) -> list[dict[str, str]]:
    rows = []
    for index in range(count):
        subject, body = templates[index % len(templates)]
        values = VARIATIONS[index % len(VARIATIONS)]
        rows.append(
            {
                "label": label,
                "subject": subject.format(**values),
                "body": body.format(**values),
            }
        )
    return rows


def main() -> None:
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows = build_rows("legitimate", LEGITIMATE_TEMPLATES, 500)
    rows.extend(build_rows("phishing", PHISHING_TEMPLATES, 500))

    with DATASET_PATH.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["label", "subject", "body"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} emails to {DATASET_PATH}")


if __name__ == "__main__":
    main()
