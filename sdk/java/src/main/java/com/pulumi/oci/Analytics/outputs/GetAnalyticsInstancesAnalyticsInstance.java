// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Analytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Analytics.outputs.GetAnalyticsInstancesAnalyticsInstanceCapacity;
import com.pulumi.oci.Analytics.outputs.GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAnalyticsInstancesAnalyticsInstance {
    /**
     * @return Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
     * 
     */
    private List<GetAnalyticsInstancesAnalyticsInstanceCapacity> capacities;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Description of the vanity url.
     * 
     */
    private String description;
    /**
     * @return Email address receiving notifications.
     * 
     */
    private String emailNotification;
    /**
     * @return A filter to only return resources matching the feature set. Values are case-insensitive.
     * 
     */
    private String featureSet;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    private String id;
    private String idcsAccessToken;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
     * 
     */
    private String kmsKeyId;
    /**
     * @return The license used for the service.
     * 
     */
    private String licenseType;
    /**
     * @return A filter to return only resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return Base representation of a network endpoint.
     * 
     */
    private List<GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail> networkEndpointDetails;
    /**
     * @return URL of the Analytics service.
     * 
     */
    private String serviceUrl;
    /**
     * @return A filter to only return resources matching the lifecycle state. The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
     * 
     */
    private String timeUpdated;

    private GetAnalyticsInstancesAnalyticsInstance() {}
    /**
     * @return Service instance capacity metadata (e.g.: OLPU count, number of users, ...etc...).
     * 
     */
    public List<GetAnalyticsInstancesAnalyticsInstanceCapacity> capacities() {
        return this.capacities;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Description of the vanity url.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Email address receiving notifications.
     * 
     */
    public String emailNotification() {
        return this.emailNotification;
    }
    /**
     * @return A filter to only return resources matching the feature set. Values are case-insensitive.
     * 
     */
    public String featureSet() {
        return this.featureSet;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    public String id() {
        return this.id;
    }
    public String idcsAccessToken() {
        return this.idcsAccessToken;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure Vault Key encrypting the customer data stored in this Analytics instance. A null value indicates Oracle managed default encryption.
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }
    /**
     * @return The license used for the service.
     * 
     */
    public String licenseType() {
        return this.licenseType;
    }
    /**
     * @return A filter to return only resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Base representation of a network endpoint.
     * 
     */
    public List<GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail> networkEndpointDetails() {
        return this.networkEndpointDetails;
    }
    /**
     * @return URL of the Analytics service.
     * 
     */
    public String serviceUrl() {
        return this.serviceUrl;
    }
    /**
     * @return A filter to only return resources matching the lifecycle state. The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the instance was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the instance was last updated (in the format defined by RFC3339). This timestamp represents updates made through this API. External events do not influence it.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAnalyticsInstancesAnalyticsInstance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAnalyticsInstancesAnalyticsInstanceCapacity> capacities;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String emailNotification;
        private String featureSet;
        private Map<String,Object> freeformTags;
        private String id;
        private String idcsAccessToken;
        private String kmsKeyId;
        private String licenseType;
        private String name;
        private List<GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail> networkEndpointDetails;
        private String serviceUrl;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAnalyticsInstancesAnalyticsInstance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.capacities = defaults.capacities;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.emailNotification = defaults.emailNotification;
    	      this.featureSet = defaults.featureSet;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.idcsAccessToken = defaults.idcsAccessToken;
    	      this.kmsKeyId = defaults.kmsKeyId;
    	      this.licenseType = defaults.licenseType;
    	      this.name = defaults.name;
    	      this.networkEndpointDetails = defaults.networkEndpointDetails;
    	      this.serviceUrl = defaults.serviceUrl;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder capacities(List<GetAnalyticsInstancesAnalyticsInstanceCapacity> capacities) {
            this.capacities = Objects.requireNonNull(capacities);
            return this;
        }
        public Builder capacities(GetAnalyticsInstancesAnalyticsInstanceCapacity... capacities) {
            return capacities(List.of(capacities));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder emailNotification(String emailNotification) {
            this.emailNotification = Objects.requireNonNull(emailNotification);
            return this;
        }
        @CustomType.Setter
        public Builder featureSet(String featureSet) {
            this.featureSet = Objects.requireNonNull(featureSet);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder idcsAccessToken(String idcsAccessToken) {
            this.idcsAccessToken = Objects.requireNonNull(idcsAccessToken);
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            this.kmsKeyId = Objects.requireNonNull(kmsKeyId);
            return this;
        }
        @CustomType.Setter
        public Builder licenseType(String licenseType) {
            this.licenseType = Objects.requireNonNull(licenseType);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder networkEndpointDetails(List<GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail> networkEndpointDetails) {
            this.networkEndpointDetails = Objects.requireNonNull(networkEndpointDetails);
            return this;
        }
        public Builder networkEndpointDetails(GetAnalyticsInstancesAnalyticsInstanceNetworkEndpointDetail... networkEndpointDetails) {
            return networkEndpointDetails(List.of(networkEndpointDetails));
        }
        @CustomType.Setter
        public Builder serviceUrl(String serviceUrl) {
            this.serviceUrl = Objects.requireNonNull(serviceUrl);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetAnalyticsInstancesAnalyticsInstance build() {
            final var o = new GetAnalyticsInstancesAnalyticsInstance();
            o.capacities = capacities;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.emailNotification = emailNotification;
            o.featureSet = featureSet;
            o.freeformTags = freeformTags;
            o.id = id;
            o.idcsAccessToken = idcsAccessToken;
            o.kmsKeyId = kmsKeyId;
            o.licenseType = licenseType;
            o.name = name;
            o.networkEndpointDetails = networkEndpointDetails;
            o.serviceUrl = serviceUrl;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}