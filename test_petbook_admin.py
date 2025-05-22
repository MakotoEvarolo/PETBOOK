from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import time

# === Config ===
BASE_URL = "http://127.0.0.1:8000"  # Update if your Flask app runs on a different port
USER_USERNAME = "sarls"
USER_PASSWORD = "123"
CHROMEDRIVER_PATH = r"C:\Users\Makoto\Desktop\chromedriver.exe"  # <-- Update path if needed

# === Setup WebDriver ===
options = Options()
# options.add_argument('--headless')  # Uncomment to run in headless mode
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

service = Service(CHROMEDRIVER_PATH)
driver = webdriver.Chrome(service=service, options=options)

# === Functional Test Functions ===

def login_as_user():
    print("[*] Logging in as user...")
    driver.get(f"{BASE_URL}/login")

    try:
        wait = WebDriverWait(driver, 10)
        username_input = wait.until(EC.presence_of_element_located((By.ID, "username")))
        password_input = wait.until(EC.presence_of_element_located((By.ID, "password")))
        login_button = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[text()='Login']")))

        username_input.send_keys(USER_USERNAME)
        password_input.send_keys(USER_PASSWORD)
        login_button.click()

        time.sleep(2)
        assert "Dashboard" in driver.page_source or "PetBook" in driver.title
        print("[✔] User login successful.")
    except Exception as e:
        print("[✘] Failed to interact with login form:", e)
        print("[✘] Page HTML snapshot:\n", driver.page_source)
        raise

def visit_user_home():
    print("[*] Visiting user home...")
    driver.get(f"{BASE_URL}/")
    time.sleep(2)
    assert "PetBook" in driver.title or "Welcome" in driver.page_source
    print("[✔] User home page loaded.")

def visit_adoption_listings():
    print("[*] Visiting adoption listings...")
    driver.find_element(By.LINK_TEXT, "Adoption Listing").click()
    time.sleep(2)
    assert "Adoption" in driver.page_source
    print("[✔] User adoption listings loaded.")

def visit_profile():
    print("[*] Visiting profile...")
    driver.find_element(By.LINK_TEXT, "Profile").click()
    time.sleep(2)
    assert "Profile" in driver.page_source
    print("[✔] User profile page loaded.")

def visit_settings():
    print("[*] Visiting settings...")
try:
    settings_link = wait.until(EC.element_to_be_clickable((By.LINK_TEXT, "Settings")))
    driver.execute_script("arguments[0].scrollIntoView(true);", settings_link)
    ActionChains(driver).move_to_element(settings_link).click().perform()
    print("[✔] Settings page loaded.")
except Exception as e:
    driver.save_screenshot("settings_click_error.png")
    print(f"[✘] Error occurred: {e}")


def logout():
    print("[*] Logging out...")
    driver.find_element(By.ID, "logoutButton").click()
    time.sleep(1)
    driver.find_element(By.LINK_TEXT, "Yes").click()
    print("[✔] Logout completed.")

# === Execute Functional Test Suite ===
try:
    login_as_user()
    visit_user_home()
    visit_adoption_listings()
    visit_profile()
    visit_settings()
    logout()
except AssertionError as ae:
    print("[✘] Assertion failed:", ae)
except Exception as e:
    print("[✘] Error occurred:", e)
finally:
    driver.quit()
    print("[*] Test suite completed and browser closed.")
