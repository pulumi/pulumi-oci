// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The description of the Database Management private endpoint.
     * 
     */
    private final String description;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    private final String id;
    /**
     * @return The option to filter Database Management private endpoints that can used for Oracle Databases in a cluster. This should be used along with the vcnId query parameter.
     * 
     */
    private final Boolean isCluster;
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private final String name;
    /**
     * @return The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
     * 
     */
    private final List<String> nsgIds;
    /**
     * @return The IP addresses assigned to the Database Management private endpoint.
     * 
     */
    private final String privateIp;
    /**
     * @return The lifecycle state of a resource.
     * 
     */
    private final String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    private final String subnetId;
    /**
     * @return The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeCreated;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    private final String vcnId;

    @CustomType.Constructor
    private GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isCluster") Boolean isCluster,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("nsgIds") List<String> nsgIds,
        @CustomType.Parameter("privateIp") String privateIp,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("subnetId") String subnetId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("vcnId") String vcnId) {
        this.compartmentId = compartmentId;
        this.description = description;
        this.id = id;
        this.isCluster = isCluster;
        this.name = name;
        this.nsgIds = nsgIds;
        this.privateIp = privateIp;
        this.state = state;
        this.subnetId = subnetId;
        this.timeCreated = timeCreated;
        this.vcnId = vcnId;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The description of the Database Management private endpoint.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The option to filter Database Management private endpoints that can used for Oracle Databases in a cluster. This should be used along with the vcnId query parameter.
     * 
     */
    public Boolean isCluster() {
        return this.isCluster;
    }
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
     * 
     */
    public List<String> nsgIds() {
        return this.nsgIds;
    }
    /**
     * @return The IP addresses assigned to the Database Management private endpoint.
     * 
     */
    public String privateIp() {
        return this.privateIp;
    }
    /**
     * @return The lifecycle state of a resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String description;
        private String id;
        private Boolean isCluster;
        private String name;
        private List<String> nsgIds;
        private String privateIp;
        private String state;
        private String subnetId;
        private String timeCreated;
        private String vcnId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.isCluster = defaults.isCluster;
    	      this.name = defaults.name;
    	      this.nsgIds = defaults.nsgIds;
    	      this.privateIp = defaults.privateIp;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vcnId = defaults.vcnId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isCluster(Boolean isCluster) {
            this.isCluster = Objects.requireNonNull(isCluster);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder nsgIds(List<String> nsgIds) {
            this.nsgIds = Objects.requireNonNull(nsgIds);
            return this;
        }
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }
        public Builder privateIp(String privateIp) {
            this.privateIp = Objects.requireNonNull(privateIp);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }        public GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem build() {
            return new GetDbManagementPrivateEndpointsDbManagementPrivateEndpointCollectionItem(compartmentId, description, id, isCluster, name, nsgIds, privateIp, state, subnetId, timeCreated, vcnId);
        }
    }
}
