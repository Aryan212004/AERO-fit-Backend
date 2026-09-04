from typing import Optional
from pydantic import BaseModel

class AdminLogin(BaseModel):
    username: str
    password: str

class AlphaLogin(BaseModel):
    username: str
    password: str

class AddUserRequest(BaseModel):
    name: str
    email: str
    password: str
    weight_kg: float
    height_cm: float
    gym_id: Optional[str] = None
    user_id: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    weight_kg: Optional[float] = None
    height_cm: Optional[float] = None

class DeleteAccountRequest(BaseModel):
    password: str

class BannerCreate(BaseModel):
    title: str
    screen: str = "home"
    status: str = "active"
    expires_at: Optional[str] = None
    deep_link: Optional[str] = None
    image_base64: Optional[str] = None
    gym_id: str

class NotificationCreate(BaseModel):
    title: str
    body: str
    type: str = "general"
    segments: list[str] = ["all"]
    deep_link: Optional[str] = None
    scheduled_at: Optional[str] = None
    gym_id: str

class GymCreate(BaseModel):
    name: str
    city: str
    plan: str = "Starter"
    admin_email: str
    admin_name: str = "Admin"
    admin_password: str = ""

class GymUpdate(BaseModel):
    name: Optional[str] = None
    city: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None
    members: Optional[int] = None

class GymAdminUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None

class ValidateUserIdRequest(BaseModel):
    user_id: str

class GenerateUserIdsRequest(BaseModel):
    count: int = 1
    plan_months: int = 1

class UpdateUserIdPlan(BaseModel):
    plan_months: int

class FcmTokenUpdate(BaseModel):
    fcm_token: str
    gym_id: str

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

class ResetPasswordRequest(BaseModel):
    email: str
    reset_token: str
    new_password: str

class IndieSendOtpRequest(BaseModel):
    email: str

class IndieVerifySignupOtpRequest(BaseModel):
    email: str
    otp: str

class AgreementSubmit(BaseModel):
    admin_name: str
    gym_name: str
    id_type: str
    id_number: str
    signature_base64: str
    id_proof_base64: str

class GymAdminForgotPasswordRequest(BaseModel):
    email: str

class GymAdminVerifyOtpRequest(BaseModel):
    email: str
    otp: str

class GymAdminResetPasswordRequest(BaseModel):
    email: str
    reset_token: str
    new_password: str

class TrainerCreate(BaseModel):
    name: str
    specialty: str
    experience_years: int = 0
    phone: str = ""
    certifications: list[str] = []

class TrainerUpdate(BaseModel):
    name: Optional[str] = None
    specialty: Optional[str] = None
    experience_years: Optional[int] = None
    phone: Optional[str] = None
    certifications: Optional[list[str]] = None

class BatchCreate(BaseModel):
    name: str
    time: str
    days_label: str
    trainer_name: str
    capacity: int = 20
    member_count: int = 0

class BatchUpdate(BaseModel):
    name: Optional[str] = None
    time: Optional[str] = None
    days_label: Optional[str] = None
    trainer_name: Optional[str] = None
    capacity: Optional[int] = None
    member_count: Optional[int] = None

class BatchEnroll(BaseModel):
    email: str

class WorkoutLockUpdate(BaseModel):
    locked: bool
    trainer_id: Optional[str] = None

class FitnessPlanUpdate(BaseModel):
    fitness_plan_text: str