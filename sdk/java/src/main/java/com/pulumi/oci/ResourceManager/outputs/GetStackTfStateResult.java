// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ResourceManager.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetStackTfStateResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String localPath;
    private final String stackId;

    @CustomType.Constructor
    private GetStackTfStateResult(
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("localPath") String localPath,
        @CustomType.Parameter("stackId") String stackId) {
        this.id = id;
        this.localPath = localPath;
        this.stackId = stackId;
    }

    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String localPath() {
        return this.localPath;
    }
    public String stackId() {
        return this.stackId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStackTfStateResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String id;
        private String localPath;
        private String stackId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetStackTfStateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.localPath = defaults.localPath;
    	      this.stackId = defaults.stackId;
        }

        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder localPath(String localPath) {
            this.localPath = Objects.requireNonNull(localPath);
            return this;
        }
        public Builder stackId(String stackId) {
            this.stackId = Objects.requireNonNull(stackId);
            return this;
        }        public GetStackTfStateResult build() {
            return new GetStackTfStateResult(id, localPath, stackId);
        }
    }
}
