class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  def admin?
    email == 'xdite@growth.school'
  end

  def admin?
  is_admin
end

has_many :resumes


  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
end
