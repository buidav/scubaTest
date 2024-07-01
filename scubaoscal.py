import json
import uuid
from datetime import datetime, timezone


'''
https://viewer.oscal.io/
view output json here
'''
class ScubaOSCAL:
    '''
    Proof of concept for creating OSCAL catalog JSON from CISA SCuBA M365 security baselines.
    Note that OSCAL Catalogs are meant for higher level control frameworks like NIST/ISO
    while SCuBA SCBs fit more at the OCSAL profile
    '''

    VERSION = '1.0'
    OSCAL_VERSION = "1.1.2"
    CATALOG_TITLE = 'CISA SCuBA Microsoft 365 Secure Configuration Baselines'
    REMARKS = '''
    The Secure Cloud Business Applications (SCuBA) project run by the Cybersecurity and Infrastructure Security Agency (CISA)
    provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies'
    cloud business application environments and protect federal information that is created, accessed,
    shared, and stored in those environments.

    The CISA SCuBA SCBs for M365 help secure federal information assets stored within M365
    cloud business application environments through consistent, effective, and manageable
    security configurations.
    CISA created baselines tailored to the federal government's threats and risk
    tolerance with the knowledge that every organization has different threat models and risk tolerance.
    Non-governmental organizations may also find value in applying these baselines to reduce risks.

    The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY.
    CISA does not endorse any commercial product or service, including any subjects of analysis.
    Any reference to specific commercial entities or commercial products, processes, or services by service mark,
    trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or
    favoritism by CISA. This document does not address, ensure compliance with, or supersede any law,
    regulation, or other authority. Entities are responsible for complying with any recordkeeping, privacy,
    and other laws that may apply to the use of technology. This document is not intended to, and does not,
    create any right or benefit for anyone against the United States, its departments, agencies, or entities,
    its officers, employees, or agents, or any other person.
    '''

    PRODUCT_TO_FULLNAME = {
        "aad": "Azure Active Directory",
        "defender": "Microsoft 365 Defender",
        "exo": "Exchange Online",
        "powerbi": "Power BI",
        "powerplatform": "Microsoft Power Platform",
        "sharepoint": "SharePoint Online",
        "teams": "Microsoft Teams",
        }

    def __init__(self, scuba_markdown):
        '''
        https://pages.nist.gov/OSCAL/learn/tutorials/control/basic-catalog/
        '''

        self.catalog = {
            "catalog": {
                "uuid": str(uuid.uuid4()),
                "metadata": self.generate_metadata(),
                "groups": self.generate_groups(scuba_markdown),
                "back-matter": {
                    "resources": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": " Secure Cloud Business Applications (SCuBA) Project ",
                            "citation": {"text": "CISA. (2024). Secure Cloud Business Applications (SCUBA) project. Cybersecurity and Infrastructure Security Agency (CISA)."},
                            "rlinks":[{"href": "https://www.cisa.gov/scuba"}]
                        },
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": "ScubaGear GitHub repository",
                            "citation": {"text": "CISA. (2024). cisagov/ScubaGear: Automation to assess the state of your M365 tenant against Cisa's baselines. GitHub."},
                            "rlinks":[{"href": "https://github.com/cisagov/ScubaGear"}]
                        },
                    ]
                }
            }
        }

    def generate_metadata(self):
        local_time = datetime.now(timezone.utc).astimezone()
        parties = str(uuid.uuid4())
        return {
              "title": self.CATALOG_TITLE,
              "published":   local_time.isoformat(),
              "last-modified": local_time.isoformat(),
              "version": self.VERSION,
              "oscal-version": self.OSCAL_VERSION,
              "remarks": self.REMARKS,
              "roles": [
                  {
                      "id": "creator",
                      "title": "Document creator"
                  },
                  {
                      "id": "contact",
                      "title": "Contact"
                  }
                  ],
                  "parties": [
                      {
                          "uuid": parties,
                          "type": "organization",
                          "name": "CISA",
                          "email-addresses": [
                              "cybersharedservices@cisa.dhs.gov"
                           ],
                           "addresses": [
                               {
                                "addr-lines": [
                                    "Cybersecurity and Infrastructure Security Agency"
                                ],
                                "city": "Washington, D.C.",
                                "state": "NA",
                                "postal-code": "TODO"
                                }
                            ]
                        }
                    ],
                    "responsible-parties": [
                        {
                            "role-id": "creator",
                            "party-uuids": [
                                parties
                            ]
                            },
                        {
                        "role-id": "contact",
                        "party-uuids": [
                            parties
                        ]
                    }
                ],
              "props": [
                  {
                      "name": "keywords",
                      "value": "Cybersecurity and Infrastructure Security Agency, CISA, Secure Cloud Business Applications, SCuBA, Microsoft 365, ScubaGear, security automation,"
                  }
              ]
            }

    def generate_groups(self, scuba_markdown):
        oscal_agg = []

        # process baselines
        baseline_count = 1
        for baseline, policy_groups in scuba_markdown.items():
            oscal_group = {}
            oscal_group['id'] = baseline
            oscal_group['title'] = self.PRODUCT_TO_FULLNAME[baseline]
            oscal_group['props'] = [
                {
                    "name": "label",
                    "value": str(baseline_count)
                }
            ]
            oscal_policy_groups = []
            # process policy groups
            for policy_group in policy_groups:
                group_id = f"MS.{baseline.upper()}.{policy_group['GroupNumber']}"#str(baseline_count) + "_" + policy_group['GroupNumber']
                group_id_smt = group_id + "_smt"
                group_prose = f"This is the {policy_group['GroupName']} policy group for the {self.PRODUCT_TO_FULLNAME[baseline]} SCuBA security configuration baseline"

                # process controls
                controls_in_group = []
                for controls in policy_group['Controls']:
                    control_component = {
                        "id": controls['Id'],
                        "title": controls['Value'],
                        "props": [{
                            "name": "label",
                            "value": controls['Id']
                        }],
                        "parts": [{
                            "id" : f"{controls['Id']}_stm",
                            "name" : "statement",
                            "prose" : f"TODO Adding additional information here requires modifications to ScubaGear/Goggles itself. To display the rationale, note, and implementation fields for this control, {controls['Id']}, enhancements need to be added to the markdown parser function in the reporter module."
                        }]
                    }
                    #
                    controls_in_group.append(control_component)
                    # end process controls
                oscal_policy_group = {
                    "id": group_id,
                    "title": policy_group['GroupName'],
                    "props": [{
                        "name": "label",
                        "value": group_id
                        }],
                    "parts": [{
                        "id": group_id_smt,
                        "name": "overview",
                        "prose": group_prose
                    }],
                    "controls": controls_in_group
                }
                #"controls": controls_in_group
                oscal_policy_groups.append(oscal_policy_group)

            oscal_group['groups'] = oscal_policy_groups
            oscal_agg.append(oscal_group)
            baseline_count += 1
        return oscal_agg


    def print_catalog(self):
        print(json.dumps(self.catalog, indent=4))

    def write_catalog(self):
        json_object = json.dumps(self.catalog, indent=4)
        with open("./scuba_m365_catalog.json", "w") as outfile:
            outfile.write(json_object)



if __name__ == '__main__':

    f = open('scubamarkdown.json', encoding='UTF-8')
    data = json.load(f)
    scuba = ScubaOSCAL(data)
    scuba.write_catalog()

