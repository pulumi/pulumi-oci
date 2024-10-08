// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceTasksTaskSummaryCollectionItemAuthConfigParentRef;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig {
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    private String key;
    /**
     * @return The type of the types object.
     * 
     */
    private String modelType;
    /**
     * @return The model version of an object.
     * 
     */
    private String modelVersion;
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    private GetWorkspaceTasksTaskSummaryCollectionItemAuthConfigParentRef parentRef;
    /**
     * @return The Oracle Cloud Infrastructure resource type that will supply the authentication token
     * 
     */
    private String resourcePrincipalSource;

    private GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig() {}
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The type of the types object.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return The model version of an object.
     * 
     */
    public String modelVersion() {
        return this.modelVersion;
    }
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    public GetWorkspaceTasksTaskSummaryCollectionItemAuthConfigParentRef parentRef() {
        return this.parentRef;
    }
    /**
     * @return The Oracle Cloud Infrastructure resource type that will supply the authentication token
     * 
     */
    public String resourcePrincipalSource() {
        return this.resourcePrincipalSource;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String modelType;
        private String modelVersion;
        private GetWorkspaceTasksTaskSummaryCollectionItemAuthConfigParentRef parentRef;
        private String resourcePrincipalSource;
        public Builder() {}
        public Builder(GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.parentRef = defaults.parentRef;
    	      this.resourcePrincipalSource = defaults.resourcePrincipalSource;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            if (modelVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig", "modelVersion");
            }
            this.modelVersion = modelVersion;
            return this;
        }
        @CustomType.Setter
        public Builder parentRef(GetWorkspaceTasksTaskSummaryCollectionItemAuthConfigParentRef parentRef) {
            if (parentRef == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig", "parentRef");
            }
            this.parentRef = parentRef;
            return this;
        }
        @CustomType.Setter
        public Builder resourcePrincipalSource(String resourcePrincipalSource) {
            if (resourcePrincipalSource == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig", "resourcePrincipalSource");
            }
            this.resourcePrincipalSource = resourcePrincipalSource;
            return this;
        }
        public GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig build() {
            final var _resultValue = new GetWorkspaceTasksTaskSummaryCollectionItemAuthConfig();
            _resultValue.key = key;
            _resultValue.modelType = modelType;
            _resultValue.modelVersion = modelVersion;
            _resultValue.parentRef = parentRef;
            _resultValue.resourcePrincipalSource = resourcePrincipalSource;
            return _resultValue;
        }
    }
}
