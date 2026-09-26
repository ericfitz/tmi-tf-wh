resource "google_compute_network" "main" {
  name                    = "tmi-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private" {
  name                     = "private"
  network                  = google_compute_network.main.id
  ip_cidr_range            = "10.2.0.0/24"
  region                   = "us-central1"
  private_ip_google_access = true
}

resource "google_compute_firewall" "allow_https" {
  name          = "allow-https"
  network       = google_compute_network.main.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_service_account" "app" {
  account_id   = "app"
  display_name = "App"
}

resource "google_storage_bucket" "data" {
  name                        = "tmi-data"
  location                    = "US"
  uniform_bucket_level_access = true
  force_destroy               = false
  labels                      = { env = "test" }
}

resource "google_compute_instance" "web" {
  name         = "web"
  machine_type = "e2-micro"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }
  metadata = {
    startup-script = "#!/bin/bash\necho hi"
    enable-oslogin = "TRUE"
  }
  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }
}
