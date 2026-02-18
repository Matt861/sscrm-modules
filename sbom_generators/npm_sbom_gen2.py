# import json
# import uuid
# import tempfile
# import os
# import shutil
# import subprocess
# import requests
# from configuration import Configuration as Config
# import utils
# from pathlib import Path
#
# p = Path(__file__).resolve()
#
#
# def fill_component_template(template, component_info):
#     return Utils.replace_placeholders(template, component_info)
#
#
# def fill_sbom_template(template, package_manager):
#     replacements = {
#         "serialNumber": str(uuid.uuid4()),
#         "component_bom_ref": f"{package_manager}-packages@0.1.0",
#         "component_name": f"{package_manager}-packages",
#         "component_version": "0.1.0",
#         "tool_vendor": "LMCO",
#         "tool_name": "SSCRM",
#         "tool_version": "0.1.0",
#         "package_manager": package_manager
#     }
#     return Utils.replace_placeholders(template, replacements)
#
#
# def generate_package_lock_json():
#     # Create a temporary directory
#     temp_dir = tempfile.mkdtemp()
#     original_dir = os.getcwd()  # Save the original directory
#
#     try:
#         # Copy package.json to the temporary directory
#         shutil.copy(Config.package_json_file_path, temp_dir)
#
#         # Change directory to the temporary directory
#         os.chdir(temp_dir)
#
#         # Run npm install to generate package-lock.json
#         subprocess.run(["npm.cmd", "install", "--package-lock-only", "--legacy-peer-deps", "--force"], check=True)
#
#         # Read the generated package-lock.json
#         with open("package-lock.json", "r") as lockfile:
#             lock_data = json.load(lockfile)
#
#         return lock_data
#
#     except subprocess.CalledProcessError as e:
#         print(f"Error running npm install: {e}")
#         return None
#     finally:
#         # Change back to the original directory
#         os.chdir(original_dir)
#
#         # Clean up: Remove the temporary directory and its contents
#         shutil.rmtree(temp_dir)
#
#
# def clean_package_name(package_name):
#     """
#     Removes any prefixes before 'node_modules/' or '/node_modules/'.
#     """
#     if 'node_modules/' in package_name:
#         package_name = package_name.lower().split('node_modules/')[-1]
#
#     return package_name
#
#
# def process_dependencies(lockfile, sbom_components, sbom_dependencies, component_template, package_manager):
#     processed_packages = set()
#     for package_name, package_data in lockfile.get("packages", {}).items():
#         if not package_data or package_name == "":
#             continue
#
#         # Clean the package name and get the version from package_data
#         clean_name = clean_package_name(package_name)
#         version = package_data.get("version", "Unknown")
#         purl = f"{clean_name}@{version}"  # Without "pkg:npm/" prefix for the bom-ref
#         parent_purl = f"pkg:{package_manager}/{purl}"  # Full purl with "pkg:{package_manager}/" prefix
#
#         if parent_purl in processed_packages:
#             continue  # Avoid processing the same package multiple times
#
#         processed_packages.add(parent_purl)
#         npm_info = fetch_npm_info(clean_name, version)
#         external_references = []
#         if npm_info.get("repository", {}):
#             external_references.append({"type": "vcs", "url": npm_info.get("repository", {}).get("url", "")})
#         # if npm_info.get("homepage", ""):
#         #     external_references.append({"type": "homepage", "url": npm_info.get("homepage", "")})
#
#         if npm_info:
#             component_info = {
#                 "component_bom_ref": purl,
#                 "component_name": clean_name,
#                 "component_version": version,
#                 "component_publisher": npm_info.get("author", {}).get("name", "Unknown"),
#                 "component_description": npm_info.get("description", "No description available"),
#                 "component_purl": purl,
#                 "license_id": npm_info.get("license", "Unknown"),
#                 "package_manager": package_manager
#             }
#
#             component = fill_component_template(component_template, component_info)
#             component["externalReferences"] = external_references
#             sbom_components.append(component)
#
#             depends_on = []
#             for dep_name, dep_data in package_data.get("dependencies", {}).items():
#                 # Handle both dictionary and string dep_data
#                 if isinstance(dep_data, dict):
#                     dep_version = dep_data.get("version", "Unknown")
#                 elif isinstance(dep_data, str):
#                     dep_version = dep_data
#                 else:
#                     dep_version = "Unknown"
#
#                 child_purl = f"pkg:{package_manager}/{dep_name.lower()}@{dep_version}"
#                 depends_on.append(child_purl)
#
#             sbom_dependencies.append({
#                 "ref": parent_purl,
#                 "dependsOn": depends_on
#             })
#
#
# def fetch_npm_info(package_name, version):
#     url = f"https://registry.npmjs.org/{package_name}/{version}"
#     proxies = {"http": "", "https": ""}
#     response = requests.get(url, proxies=proxies, verify=Config.cert_file)
#     if response.status_code == 200:
#         return response.json()
#     else:
#         print(f"Failed to fetch data for {package_name}@{version}")
#         return None
#
#
# def add_top_level_dependencies(sbom, package_json, package_manager):
#     top_level_dependencies = package_json.get("dependencies", {})
#     top_level_refs = [
#         f"pkg:{package_manager}/{dep_name}@{dep_version.lstrip('^~<>')}"
#         for dep_name, dep_version in top_level_dependencies.items()
#     ]
#
#     top_level_entry = {
#         "ref": sbom["metadata"]["component"]["bom-ref"],
#         "dependsOn": top_level_refs
#     }
#
#     sbom["dependencies"].insert(0, top_level_entry)
#
#
# def generate_sbom_npm_from_lockfile(lockfile, package_manager, package_json):
#     # Load the SBOM and component templates
#     sbom_template = utils.load_json_file(os.path.join(Config.root_dir, 'templates/sbom_template.json'))
#     component_template = utils.load_json_file(os.path.join(Config.root_dir, 'templates/sbom_component_template.json'))
#
#     sbom = fill_sbom_template(sbom_template, package_manager)
#     process_dependencies(lockfile, sbom["components"], sbom["dependencies"], component_template, package_manager)
#     add_top_level_dependencies(sbom, package_json, package_manager)
#
#     return sbom
#
#
# def main():
#     print('Executing NPM SBOM generation')
#     Config.package_json_file_path = Path(Config.sbom_input_dir, Config.package_json_file_name)
#     Config.package_lock_json_file_path = Path(Config.sbom_input_dir, Config.package_lock_json_file_name)
#     Config.npmrc_file_path = Path(Config.sbom_input_dir, Config.npmrc_file_name)
#     Config.sbom_output_file_name = f"{Config.project_name}-{Config.project_version}-sbom"
#     Config.sbom_output_file_path = Path(Config.project_output_dir, f"{Config.sbom_output_file_name}.{Config.sbom_format}")
#
#     # Set your package manager here
#     package_manager = "npm"
#     # Load the package.json file
#     package_json = utils.load_json_file(os.path.join(Config.root_dir, 'input/package.json'))
#     # Generate package-lock.json in a temporary environment
#     lockfile = generate_package_lock_json()
#
#     if lockfile is None:
#         print("Failed to generate package-lock.json")
#         return
#
#     sbom = generate_sbom_npm_from_lockfile(lockfile, package_manager, package_json)
#     Config.sbom = sbom
#
#     # Write SBOM to a file
#     output_file = os.path.join(Config.output_dir, f"sbom_{Config.timestamp}.json")
#     Config.sbom_path = output_file
#     Utils.write_json_file(sbom, output_file)
#
#     print(f"Successfully generated file: {Config.sbom_path}")
#
#
# if __name__ == "__main__":
#     main()
#
#
# def run():
#     main()
