// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetBdsInstancePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstancePlainArgs Empty = new GetBdsInstancePlainArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private String bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }

    private GetBdsInstancePlainArgs() {}

    private GetBdsInstancePlainArgs(GetBdsInstancePlainArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstancePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstancePlainArgs $;

        public Builder() {
            $ = new GetBdsInstancePlainArgs();
        }

        public Builder(GetBdsInstancePlainArgs defaults) {
            $ = new GetBdsInstancePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        public GetBdsInstancePlainArgs build() {
            $.bdsInstanceId = Objects.requireNonNull($.bdsInstanceId, "expected parameter 'bdsInstanceId' to be non-null");
            return $;
        }
    }

}