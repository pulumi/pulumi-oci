// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceManagerProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetServiceEnvironmentsServiceEnvironmentCollectionItem {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The URL for the console.
     * 
     */
    private String consoleUrl;
    private Map<String,String> definedTags;
    private Map<String,String> freeformTags;
    /**
     * @return Unqiue identifier for the entitlement related to the environment.
     * 
     */
    private String id;
    /**
     * @return Details for a service definition.
     * 
     */
    private List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition> serviceDefinitions;
    /**
     * @return Array of service environment end points.
     * 
     */
    private List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint> serviceEnvironmentEndpoints;
    /**
     * @return Status of the entitlement registration for the service.
     * 
     */
    private String status;
    /**
     * @return The unique subscription ID associated with the service environment ID.
     * 
     */
    private String subscriptionId;

    private GetServiceEnvironmentsServiceEnvironmentCollectionItem() {}
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
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unqiue identifier for the entitlement related to the environment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details for a service definition.
     * 
     */
    public List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition> serviceDefinitions() {
        return this.serviceDefinitions;
    }
    /**
     * @return Array of service environment end points.
     * 
     */
    public List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint> serviceEnvironmentEndpoints() {
        return this.serviceEnvironmentEndpoints;
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

    public static Builder builder(GetServiceEnvironmentsServiceEnvironmentCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String consoleUrl;
        private Map<String,String> definedTags;
        private Map<String,String> freeformTags;
        private String id;
        private List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition> serviceDefinitions;
        private List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint> serviceEnvironmentEndpoints;
        private String status;
        private String subscriptionId;
        public Builder() {}
        public Builder(GetServiceEnvironmentsServiceEnvironmentCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.consoleUrl = defaults.consoleUrl;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.serviceDefinitions = defaults.serviceDefinitions;
    	      this.serviceEnvironmentEndpoints = defaults.serviceEnvironmentEndpoints;
    	      this.status = defaults.status;
    	      this.subscriptionId = defaults.subscriptionId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder consoleUrl(String consoleUrl) {
            if (consoleUrl == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "consoleUrl");
            }
            this.consoleUrl = consoleUrl;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder serviceDefinitions(List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition> serviceDefinitions) {
            if (serviceDefinitions == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "serviceDefinitions");
            }
            this.serviceDefinitions = serviceDefinitions;
            return this;
        }
        public Builder serviceDefinitions(GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceDefinition... serviceDefinitions) {
            return serviceDefinitions(List.of(serviceDefinitions));
        }
        @CustomType.Setter
        public Builder serviceEnvironmentEndpoints(List<GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint> serviceEnvironmentEndpoints) {
            if (serviceEnvironmentEndpoints == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "serviceEnvironmentEndpoints");
            }
            this.serviceEnvironmentEndpoints = serviceEnvironmentEndpoints;
            return this;
        }
        public Builder serviceEnvironmentEndpoints(GetServiceEnvironmentsServiceEnvironmentCollectionItemServiceEnvironmentEndpoint... serviceEnvironmentEndpoints) {
            return serviceEnvironmentEndpoints(List.of(serviceEnvironmentEndpoints));
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionId(String subscriptionId) {
            if (subscriptionId == null) {
              throw new MissingRequiredPropertyException("GetServiceEnvironmentsServiceEnvironmentCollectionItem", "subscriptionId");
            }
            this.subscriptionId = subscriptionId;
            return this;
        }
        public GetServiceEnvironmentsServiceEnvironmentCollectionItem build() {
            final var _resultValue = new GetServiceEnvironmentsServiceEnvironmentCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.consoleUrl = consoleUrl;
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.serviceDefinitions = serviceDefinitions;
            _resultValue.serviceEnvironmentEndpoints = serviceEnvironmentEndpoints;
            _resultValue.status = status;
            _resultValue.subscriptionId = subscriptionId;
            return _resultValue;
        }
    }
}
