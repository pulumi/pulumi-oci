// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAuditProfilePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAuditProfilePlainArgs Empty = new GetAuditProfilePlainArgs();

    /**
     * The OCID of the audit.
     * 
     */
    @Import(name="auditProfileId", required=true)
    private String auditProfileId;

    /**
     * @return The OCID of the audit.
     * 
     */
    public String auditProfileId() {
        return this.auditProfileId;
    }

    private GetAuditProfilePlainArgs() {}

    private GetAuditProfilePlainArgs(GetAuditProfilePlainArgs $) {
        this.auditProfileId = $.auditProfileId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAuditProfilePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAuditProfilePlainArgs $;

        public Builder() {
            $ = new GetAuditProfilePlainArgs();
        }

        public Builder(GetAuditProfilePlainArgs defaults) {
            $ = new GetAuditProfilePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param auditProfileId The OCID of the audit.
         * 
         * @return builder
         * 
         */
        public Builder auditProfileId(String auditProfileId) {
            $.auditProfileId = auditProfileId;
            return this;
        }

        public GetAuditProfilePlainArgs build() {
            $.auditProfileId = Objects.requireNonNull($.auditProfileId, "expected parameter 'auditProfileId' to be non-null");
            return $;
        }
    }

}