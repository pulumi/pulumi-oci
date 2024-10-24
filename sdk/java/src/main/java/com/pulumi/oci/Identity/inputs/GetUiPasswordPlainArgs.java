// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetUiPasswordPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUiPasswordPlainArgs Empty = new GetUiPasswordPlainArgs();

    /**
     * The OCID of the user.
     * 
     */
    @Import(name="userId", required=true)
    private String userId;

    /**
     * @return The OCID of the user.
     * 
     */
    public String userId() {
        return this.userId;
    }

    private GetUiPasswordPlainArgs() {}

    private GetUiPasswordPlainArgs(GetUiPasswordPlainArgs $) {
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUiPasswordPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUiPasswordPlainArgs $;

        public Builder() {
            $ = new GetUiPasswordPlainArgs();
        }

        public Builder(GetUiPasswordPlainArgs defaults) {
            $ = new GetUiPasswordPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            $.userId = userId;
            return this;
        }

        public GetUiPasswordPlainArgs build() {
            if ($.userId == null) {
                throw new MissingRequiredPropertyException("GetUiPasswordPlainArgs", "userId");
            }
            return $;
        }
    }

}
