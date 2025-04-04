// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerInstances.outputs.GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck {
    private String failureAction;
    private Integer failureThreshold;
    private List<GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader> headers;
    private String healthCheckType;
    private Integer initialDelayInSeconds;
    private Integer intervalInSeconds;
    /**
     * @return The name of the volume. This must be unique within a single container instance.
     * 
     */
    private String name;
    /**
     * @return (Optional) Relative path for this file inside the volume mount directory. By default, the file is presented at the root of the volume mount path.
     * 
     */
    private String path;
    private Integer port;
    private String status;
    private String statusDetails;
    private Integer successThreshold;
    private Integer timeoutInSeconds;

    private GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck() {}
    public String failureAction() {
        return this.failureAction;
    }
    public Integer failureThreshold() {
        return this.failureThreshold;
    }
    public List<GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader> headers() {
        return this.headers;
    }
    public String healthCheckType() {
        return this.healthCheckType;
    }
    public Integer initialDelayInSeconds() {
        return this.initialDelayInSeconds;
    }
    public Integer intervalInSeconds() {
        return this.intervalInSeconds;
    }
    /**
     * @return The name of the volume. This must be unique within a single container instance.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Optional) Relative path for this file inside the volume mount directory. By default, the file is presented at the root of the volume mount path.
     * 
     */
    public String path() {
        return this.path;
    }
    public Integer port() {
        return this.port;
    }
    public String status() {
        return this.status;
    }
    public String statusDetails() {
        return this.statusDetails;
    }
    public Integer successThreshold() {
        return this.successThreshold;
    }
    public Integer timeoutInSeconds() {
        return this.timeoutInSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String failureAction;
        private Integer failureThreshold;
        private List<GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader> headers;
        private String healthCheckType;
        private Integer initialDelayInSeconds;
        private Integer intervalInSeconds;
        private String name;
        private String path;
        private Integer port;
        private String status;
        private String statusDetails;
        private Integer successThreshold;
        private Integer timeoutInSeconds;
        public Builder() {}
        public Builder(GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.failureAction = defaults.failureAction;
    	      this.failureThreshold = defaults.failureThreshold;
    	      this.headers = defaults.headers;
    	      this.healthCheckType = defaults.healthCheckType;
    	      this.initialDelayInSeconds = defaults.initialDelayInSeconds;
    	      this.intervalInSeconds = defaults.intervalInSeconds;
    	      this.name = defaults.name;
    	      this.path = defaults.path;
    	      this.port = defaults.port;
    	      this.status = defaults.status;
    	      this.statusDetails = defaults.statusDetails;
    	      this.successThreshold = defaults.successThreshold;
    	      this.timeoutInSeconds = defaults.timeoutInSeconds;
        }

        @CustomType.Setter
        public Builder failureAction(String failureAction) {
            if (failureAction == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "failureAction");
            }
            this.failureAction = failureAction;
            return this;
        }
        @CustomType.Setter
        public Builder failureThreshold(Integer failureThreshold) {
            if (failureThreshold == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "failureThreshold");
            }
            this.failureThreshold = failureThreshold;
            return this;
        }
        @CustomType.Setter
        public Builder headers(List<GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader> headers) {
            if (headers == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "headers");
            }
            this.headers = headers;
            return this;
        }
        public Builder headers(GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheckHeader... headers) {
            return headers(List.of(headers));
        }
        @CustomType.Setter
        public Builder healthCheckType(String healthCheckType) {
            if (healthCheckType == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "healthCheckType");
            }
            this.healthCheckType = healthCheckType;
            return this;
        }
        @CustomType.Setter
        public Builder initialDelayInSeconds(Integer initialDelayInSeconds) {
            if (initialDelayInSeconds == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "initialDelayInSeconds");
            }
            this.initialDelayInSeconds = initialDelayInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder intervalInSeconds(Integer intervalInSeconds) {
            if (intervalInSeconds == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "intervalInSeconds");
            }
            this.intervalInSeconds = intervalInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder statusDetails(String statusDetails) {
            if (statusDetails == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "statusDetails");
            }
            this.statusDetails = statusDetails;
            return this;
        }
        @CustomType.Setter
        public Builder successThreshold(Integer successThreshold) {
            if (successThreshold == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "successThreshold");
            }
            this.successThreshold = successThreshold;
            return this;
        }
        @CustomType.Setter
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            if (timeoutInSeconds == null) {
              throw new MissingRequiredPropertyException("GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck", "timeoutInSeconds");
            }
            this.timeoutInSeconds = timeoutInSeconds;
            return this;
        }
        public GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck build() {
            final var _resultValue = new GetContainerInstancesContainerInstanceCollectionItemContainerHealthCheck();
            _resultValue.failureAction = failureAction;
            _resultValue.failureThreshold = failureThreshold;
            _resultValue.headers = headers;
            _resultValue.healthCheckType = healthCheckType;
            _resultValue.initialDelayInSeconds = initialDelayInSeconds;
            _resultValue.intervalInSeconds = intervalInSeconds;
            _resultValue.name = name;
            _resultValue.path = path;
            _resultValue.port = port;
            _resultValue.status = status;
            _resultValue.statusDetails = statusDetails;
            _resultValue.successThreshold = successThreshold;
            _resultValue.timeoutInSeconds = timeoutInSeconds;
            return _resultValue;
        }
    }
}
