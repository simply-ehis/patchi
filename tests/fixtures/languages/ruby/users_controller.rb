class User < ApplicationRecord
  validates :name, presence: true
  validates :email, presence: true, uniqueness: true
end

class UsersController < ApplicationController
  def index
    @users = User.all
    render json: { items: @users, count: @users.count }
  end

  def show
    @user = User.find(params[:id])
    render json: { item: @user }
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Not found" }, status: :not_found
  end

  def create
    @user = User.new(user_params)
    if @user.save
      render json: { item: @user }, status: :created
    else
      render json: { errors: @user.errors }, status: :unprocessable_entity
    end
  end

  def update
    @user = User.find(params[:id])
    if @user.update(user_params)
      render json: { item: @user }
    else
      render json: { errors: @user.errors }, status: :unprocessable_entity
    end
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Not found" }, status: :not_found
  end

  def destroy
    @user = User.find(params[:id])
    @user.destroy
    render json: { message: "Deleted" }
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Not found" }, status: :not_found
  end

  def search
    query = params[:q] || ""
    @users = User.where("name LIKE ?", "%#{query}%")
    render json: { results: @users }
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end

  def unused_helper
    "dead code"
  end
end
