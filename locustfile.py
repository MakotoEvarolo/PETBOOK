from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    def on_start(self):
        # Login as regular user
        self.login("user@example.com", "password")

    def login(self, email, password):
        self.client.post("/login", data={
            "email": email,
            "password": password
        })

    @task(2)
    def home_page(self):
        self.client.get("/home")

    @task(1)
    def adoption_listings(self):
        self.client.get("/adoption_listings")

    @task(1)
    def profile(self):
        self.client.get("/profile")

    @task(1)
    def settings(self):
        self.client.get("/settings")


class AdminBehavior(TaskSet):
    def on_start(self):
        # Login as admin user
        self.login("admin@example.com", "adminpass")

    def login(self, email, password):
        self.client.post("/login", data={
            "email": email,
            "password": password
        })

    @task(2)
    def admin_home(self):
        self.client.get("/admin/home")

    @task(1)
    def admin_adoption(self):
        self.client.get("/admin/adoption_listings")

    @task(1)
    def admin_profile(self):
        self.client.get("/admin/profile")

    @task(1)
    def admin_settings(self):
        self.client.get("/admin/settings")


class RegularUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)

class AdminUser(HttpUser):
    tasks = [AdminBehavior]
    wait_time = between(2, 6)
