from typing import List, Dict, Any, Optional, Tuple

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

    def __str__(self):
        return f"AzionResource(name={self.name}, attributes={self.azion_resources})"

    @classmethod
    def get_azion_resources(cls) -> List[Dict[str, Any]]:
        """
        Returns a list of all Azion resources mapped.

        Returns:
            List[Dict[str, Any]]: The list of all Azion resources.
        """
        return cls.azion_resources

    @classmethod
    def query_azion_resource_by_type(
        cls, 
        resource_type: str,
        name: Optional[str] = None
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        """
        Query a list of Azion resources by the 'type' field. Return the first matching resource.

        Parameters:
            resource_type (str): The value of the 'type' field to search for.
            name (Optional[str]): The value of the 'name' field to search for.

        Returns:
            Optional[Dict[str, Any]]: The first resource with the matching 'type', or None if not found.
        """
        resources = cls.get_azion_resources()
        for index, resource in enumerate(resources):
            if resource.get("type") == resource_type and (name is None or resource.get("name") == name):
                return index, resource
        return -1, None

    @classmethod
    def query_all_azion_resource_by_type(cls, resource_type: str) -> List[Optional[Dict[str, Any]]]:
        """
        Query a list of Azion resources by the 'type' field. Return all matching resources.

        Parameters:
            resource_type (str): The value of the 'type' field to search for.

        Returns:
            List[Optional[Dict[str, Any]]]: A list of resources with the matching 'type', or an empty list if not found.
        """
        resources = cls.get_azion_resources()
        matched_resources = []
        for index, resource in enumerate(resources):
            if resource.get("type") == resource_type:
                matched_resources.append((index, resource))
        return matched_resources

    @classmethod
    def query_azion_origin_by_address(cls, origin_address: str) -> Optional[Dict[str, Any]]:
        """
        Query a list of Azion resource by origin resources by the 'origin_address' field. Return the
        first matching resource.

        Parameters:
            origin_address (str): The value of the 'origin_address' field to search for.

        Returns:
            Optional[Dict[str, Any]]: The first resource with the matching 'origin_address', or None 
            if not found.
        """
        origins = cls.query_all_azion_resource_by_type('azion_edge_application_origin')
        for _, origin in origins:
            origin_attributes = origin.get("attributes", {})
            origin_addresses = origin_attributes.get("origin", {}).get("addresses", [])
            for origin_addr in origin_addresses:
                if origin_addr.get("address") == origin_address:
                    return origin
        return None

    def append(self, resource: Optional[Dict[str, Any]]) -> None:
        """
        Append a new resource to the resources list.

        Parameters:
            resource (Dict[str, Any]): The resource to append.
        """
        if resource is not None:
            AzionResource.azion_resources.append(resource)
    
    def extend(self, resources: List[Dict[str, Any]]) -> None:
        """
        Extend the resources list with new resources.

        Parameters:
            resources (List[Dict[str, Any]]): The list of resources to extend.
        """
        AzionResource.azion_resources.extend(resources)

    def len(self) -> int:
        return len(AzionResource.azion_resources)
