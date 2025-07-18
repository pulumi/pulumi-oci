// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetConfigurationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConfigurationPlainArgs Empty = new GetConfigurationPlainArgs();

    /**
     * The ID of a table&#39;s compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of a table&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    private GetConfigurationPlainArgs() {}

    private GetConfigurationPlainArgs(GetConfigurationPlainArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConfigurationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConfigurationPlainArgs $;

        public Builder() {
            $ = new GetConfigurationPlainArgs();
        }

        public Builder(GetConfigurationPlainArgs defaults) {
            $ = new GetConfigurationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of a table&#39;s compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public GetConfigurationPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetConfigurationPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
