from typing import List, Dict, Any, Optional

class AzionResource:
    # Class-level attribute to store resources
    azion_resources: List[Dict[str, Any]] = []

    def __init__(self, name: str):
        """
        Initialize an AzionResource instance.

        Parameters:
            name (str): The name of the resource.
            attributes (Dict[str, Any]): The attributes of the resource.
        """
        self.name = name

    @classmethod
    def get_azion_resources(cls) -> List[Dict[str, Any]]:
        """
        Returns a list of all Azion resources mapped.

        Returns:
            List[Dict[str, Any]]: The list of all Azion resources.
        """
        return cls.azion_resources

    @classmethod
    def query_azion_resource_by_type(cls, resource_type: str) -> Optional[Dict[str, Any]]:
        """
        Query a list of Azion resources by the 'type' field.

        Parameters:
            resource_type (str): The value of the 'type' field to search for.

        Returns:
            Optional[Dict[str, Any]]: The first resource with the matching 'type', or None if not found.
        """
        resources = cls.get_azion_resources()
        for resource in resources:
            # Assuming "type" is part of the "attributes" dictionary
            if resource.get("type") == resource_type:
                return resource
        return None

    def __str__(self):
        return f"AzionResource(name={self.name}, attributes={self.azion_resources})"

    def len(self):
        return len(AzionResource.azion_resources)

    def extend(self, resources: List[Dict[str, Any]]):
        """
        Extend the resources list with new resources.

        Parameters:
            resources (List[Dict[str, Any]]): The list of resources to extend.
        """
        AzionResource.azion_resources.extend(resources)

    def append(self, resource: Optional[Dict[str, Any]]):
        """
        Append a new resource to the resources list.

        Parameters:
            resource (Dict[str, Any]): The resource to append.
        """
        if resource is not None:
            AzionResource.azion_resources.append(resource)
