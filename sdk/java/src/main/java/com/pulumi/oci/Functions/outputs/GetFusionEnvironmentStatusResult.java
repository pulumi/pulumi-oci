// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentStatusResult {
    private String fusionEnvironmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The data plane status of FusionEnvironment.
     * 
     */
    private String status;

    private GetFusionEnvironmentStatusResult() {}
    public String fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The data plane status of FusionEnvironment.
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentStatusResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String fusionEnvironmentId;
        private String id;
        private String status;
        public Builder() {}
        public Builder(GetFusionEnvironmentStatusResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fusionEnvironmentId = defaults.fusionEnvironmentId;
    	      this.id = defaults.id;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            this.fusionEnvironmentId = Objects.requireNonNull(fusionEnvironmentId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetFusionEnvironmentStatusResult build() {
            final var o = new GetFusionEnvironmentStatusResult();
            o.fusionEnvironmentId = fusionEnvironmentId;
            o.id = id;
            o.status = status;
            return o;
        }
    }
}