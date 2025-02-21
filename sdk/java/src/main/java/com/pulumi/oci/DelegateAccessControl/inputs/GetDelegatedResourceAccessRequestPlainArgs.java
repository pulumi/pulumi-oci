// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DelegateAccessControl.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDelegatedResourceAccessRequestPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDelegatedResourceAccessRequestPlainArgs Empty = new GetDelegatedResourceAccessRequestPlainArgs();

    /**
     * Unique Delegated Resource Access Request identifier
     * 
     */
    @Import(name="delegatedResourceAccessRequestId", required=true)
    private String delegatedResourceAccessRequestId;

    /**
     * @return Unique Delegated Resource Access Request identifier
     * 
     */
    public String delegatedResourceAccessRequestId() {
        return this.delegatedResourceAccessRequestId;
    }

    private GetDelegatedResourceAccessRequestPlainArgs() {}

    private GetDelegatedResourceAccessRequestPlainArgs(GetDelegatedResourceAccessRequestPlainArgs $) {
        this.delegatedResourceAccessRequestId = $.delegatedResourceAccessRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDelegatedResourceAccessRequestPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDelegatedResourceAccessRequestPlainArgs $;

        public Builder() {
            $ = new GetDelegatedResourceAccessRequestPlainArgs();
        }

        public Builder(GetDelegatedResourceAccessRequestPlainArgs defaults) {
            $ = new GetDelegatedResourceAccessRequestPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param delegatedResourceAccessRequestId Unique Delegated Resource Access Request identifier
         * 
         * @return builder
         * 
         */
        public Builder delegatedResourceAccessRequestId(String delegatedResourceAccessRequestId) {
            $.delegatedResourceAccessRequestId = delegatedResourceAccessRequestId;
            return this;
        }

        public GetDelegatedResourceAccessRequestPlainArgs build() {
            if ($.delegatedResourceAccessRequestId == null) {
                throw new MissingRequiredPropertyException("GetDelegatedResourceAccessRequestPlainArgs", "delegatedResourceAccessRequestId");
            }
            return $;
        }
    }

}
