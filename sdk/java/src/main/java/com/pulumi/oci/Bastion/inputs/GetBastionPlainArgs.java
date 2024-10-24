// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBastionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBastionPlainArgs Empty = new GetBastionPlainArgs();

    /**
     * The unique identifier (OCID) of the bastion.
     * 
     */
    @Import(name="bastionId", required=true)
    private String bastionId;

    /**
     * @return The unique identifier (OCID) of the bastion.
     * 
     */
    public String bastionId() {
        return this.bastionId;
    }

    private GetBastionPlainArgs() {}

    private GetBastionPlainArgs(GetBastionPlainArgs $) {
        this.bastionId = $.bastionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBastionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBastionPlainArgs $;

        public Builder() {
            $ = new GetBastionPlainArgs();
        }

        public Builder(GetBastionPlainArgs defaults) {
            $ = new GetBastionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bastionId The unique identifier (OCID) of the bastion.
         * 
         * @return builder
         * 
         */
        public Builder bastionId(String bastionId) {
            $.bastionId = bastionId;
            return this;
        }

        public GetBastionPlainArgs build() {
            if ($.bastionId == null) {
                throw new MissingRequiredPropertyException("GetBastionPlainArgs", "bastionId");
            }
            return $;
        }
    }

}
