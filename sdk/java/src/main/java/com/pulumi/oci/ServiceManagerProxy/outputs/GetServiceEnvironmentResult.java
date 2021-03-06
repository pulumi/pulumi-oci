// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceManagerProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentServiceDefinition;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentServiceEnvironmentEndpoint;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceEnvironmentResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The URL for the console.
     * 
     */
    private final String consoleUrl;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Details for a service definition.
     * 
     */
    private final List<GetServiceEnvironmentServiceDefinition> serviceDefinitions;
    /**
     * @return Array of service environment end points.
     * 
     */
    private final List<GetServiceEnvironmentServiceEnvironmentEndpoint> serviceEnvironmentEndpoints;
    private final String serviceEnvironmentId;
    /**
     * @return Status of the entitlement registration for the service.
     * 
     */
    private final String status;
    /**
     * @return The unique subscription ID associated with the service environment ID.
     * 
     */
    private final String subscriptionId;

    @CustomType.Constructor
    private GetServiceEnvironmentResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("consoleUrl") String consoleUrl,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("serviceDefinitions") List<GetServiceEnvironmentServiceDefinition> serviceDefinitions,
        @CustomType.Parameter("serviceEnvironmentEndpoints") List<GetServiceEnvironmentServiceEnvironmentEndpoint> serviceEnvironmentEndpoints,
        @CustomType.Parameter("serviceEnvironmentId") String serviceEnvironmentId,
        @CustomType.Parameter("status") String status,
        @CustomType.Parameter("subscriptionId") String subscriptionId) {
        this.compartmentId = compartmentId;
        this.consoleUrl = consoleUrl;
        this.id = id;
        this.serviceDefinitions = serviceDefinitions;
        this.serviceEnvironmentEndpoints = serviceEnvironmentEndpoints;
        this.serviceEnvironmentId = serviceEnvironmentId;
        this.status = status;
        this.subscriptionId = subscriptionId;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The URL for the console.
     * 
     */
    public String consoleUrl() {
        return this.consoleUrl;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details for a service definition.
     * 
     */
    public List<GetServiceEnvironmentServiceDefinition> serviceDefinitions() {
        return this.serviceDefinitions;
    }
    /**
     * @return Array of service environment end points.
     * 
     */
    public List<GetServiceEnvironmentServiceEnvironmentEndpoint> serviceEnvironmentEndpoints() {
        return this.serviceEnvironmentEndpoints;
    }
    public String serviceEnvironmentId() {
        return this.serviceEnvironmentId;
    }
    /**
     * @return Status of the entitlement registration for the service.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The unique subscription ID associated with the service environment ID.
     * 
     */
    public String subscriptionId() {
        return this.subscriptionId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceEnvironmentResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String consoleUrl;
        private String id;
        private List<GetServiceEnvironmentServiceDefinition> serviceDefinitions;
        private List<GetServiceEnvironmentServiceEnvironmentEndpoint> serviceEnvironmentEndpoints;
        private String serviceEnvironmentId;
        private String status;
        private String subscriptionId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetServiceEnvironmentResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.consoleUrl = defaults.consoleUrl;
    	      this.id = defaults.id;
    	      this.serviceDefinitions = defaults.serviceDefinitions;
    	      this.serviceEnvironmentEndpoints = defaults.serviceEnvironmentEndpoints;
    	      this.serviceEnvironmentId = defaults.serviceEnvironmentId;
    	      this.status = defaults.status;
    	      this.subscriptionId = defaults.subscriptionId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder consoleUrl(String consoleUrl) {
            this.consoleUrl = Objects.requireNonNull(consoleUrl);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder serviceDefinitions(List<GetServiceEnvironmentServiceDefinition> serviceDefinitions) {
            this.serviceDefinitions = Objects.requireNonNull(serviceDefinitions);
            return this;
        }
        public Builder serviceDefinitions(GetServiceEnvironmentServiceDefinition... serviceDefinitions) {
            return serviceDefinitions(List.of(serviceDefinitions));
        }
        public Builder serviceEnvironmentEndpoints(List<GetServiceEnvironmentServiceEnvironmentEndpoint> serviceEnvironmentEndpoints) {
            this.serviceEnvironmentEndpoints = Objects.requireNonNull(serviceEnvironmentEndpoints);
            return this;
        }
        public Builder serviceEnvironmentEndpoints(GetServiceEnvironmentServiceEnvironmentEndpoint... serviceEnvironmentEndpoints) {
            return serviceEnvironmentEndpoints(List.of(serviceEnvironmentEndpoints));
        }
        public Builder serviceEnvironmentId(String serviceEnvironmentId) {
            this.serviceEnvironmentId = Objects.requireNonNull(serviceEnvironmentId);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public Builder subscriptionId(String subscriptionId) {
            this.subscriptionId = Objects.requireNonNull(subscriptionId);
            return this;
        }        public GetServiceEnvironmentResult build() {
            return new GetServiceEnvironmentResult(compartmentId, consoleUrl, id, serviceDefinitions, serviceEnvironmentEndpoints, serviceEnvironmentId, status, subscriptionId);
        }
    }
}
