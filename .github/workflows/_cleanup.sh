#!/bin/bash

# Function to delete artifacts
delete_artifacts() {
  echo "Deleting artifacts..."
  # Add commands to delete artifacts
  # For example:
  # rm -rf /path/to/artifacts
}

# Function to delete temporary files
delete_temporary_files() {
  echo "Deleting temporary files..."
  # Add commands to delete temporary files
  # For example:
  # rm -rf /path/to/temporary/files
}

# Function to delete workspace directory
delete_workspace() {
  echo "Deleting workspace directory..."
  # Add commands to delete workspace directory
  # For example:
  /usr/local/bin/k3s-uninstall.sh

  
}

# Cleanup function
cleanup() {
  echo "Performing cleanup..."

#   delete_artifacts
#   delete_temporary_files
  delete_workspace

  echo "Cleanup complete."
}

# Invoke the cleanup function
cleanup