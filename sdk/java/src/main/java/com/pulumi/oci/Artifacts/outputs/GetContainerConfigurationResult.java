// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetContainerConfigurationResult {
    private String compartmentId;
    private String id;
    /**
     * @return Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    private Boolean isRepositoryCreatedOnFirstPush;
    /**
     * @return The tenancy namespace used in the container repository path.
     * 
     */
    private String namespace;

    private GetContainerConfigurationResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
     * 
     */
    public Boolean isRepositoryCreatedOnFirstPush() {
        return this.isRepositoryCreatedOnFirstPush;
    }
    /**
     * @return The tenancy namespace used in the container repository path.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerConfigurationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String id;
        private Boolean isRepositoryCreatedOnFirstPush;
        private String namespace;
        public Builder() {}
        public Builder(GetContainerConfigurationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.isRepositoryCreatedOnFirstPush = defaults.isRepositoryCreatedOnFirstPush;
    	      this.namespace = defaults.namespace;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetContainerConfigurationResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetContainerConfigurationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isRepositoryCreatedOnFirstPush(Boolean isRepositoryCreatedOnFirstPush) {
            if (isRepositoryCreatedOnFirstPush == null) {
              throw new MissingRequiredPropertyException("GetContainerConfigurationResult", "isRepositoryCreatedOnFirstPush");
            }
            this.isRepositoryCreatedOnFirstPush = isRepositoryCreatedOnFirstPush;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetContainerConfigurationResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        public GetContainerConfigurationResult build() {
            final var _resultValue = new GetContainerConfigurationResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.id = id;
            _resultValue.isRepositoryCreatedOnFirstPush = isRepositoryCreatedOnFirstPush;
            _resultValue.namespace = namespace;
            return _resultValue;
        }
    }
}
