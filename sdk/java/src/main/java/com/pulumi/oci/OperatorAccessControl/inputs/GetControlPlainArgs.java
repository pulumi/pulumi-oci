// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OperatorAccessControl.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetControlPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetControlPlainArgs Empty = new GetControlPlainArgs();

    /**
     * unique OperatorControl identifier
     * 
     */
    @Import(name="operatorControlId", required=true)
    private String operatorControlId;

    /**
     * @return unique OperatorControl identifier
     * 
     */
    public String operatorControlId() {
        return this.operatorControlId;
    }

    private GetControlPlainArgs() {}

    private GetControlPlainArgs(GetControlPlainArgs $) {
        this.operatorControlId = $.operatorControlId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetControlPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetControlPlainArgs $;

        public Builder() {
            $ = new GetControlPlainArgs();
        }

        public Builder(GetControlPlainArgs defaults) {
            $ = new GetControlPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param operatorControlId unique OperatorControl identifier
         * 
         * @return builder
         * 
         */
        public Builder operatorControlId(String operatorControlId) {
            $.operatorControlId = operatorControlId;
            return this;
        }

        public GetControlPlainArgs build() {
            if ($.operatorControlId == null) {
                throw new MissingRequiredPropertyException("GetControlPlainArgs", "operatorControlId");
            }
            return $;
        }
    }

}
