// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAuditProfileCollectedAuditVolumeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAuditProfileCollectedAuditVolumeArgs Empty = new GetAuditProfileCollectedAuditVolumeArgs();

    /**
     * The OCID of the audit.
     * 
     */
    @Import(name="auditProfileId", required=true)
    private Output<String> auditProfileId;

    /**
     * @return The OCID of the audit.
     * 
     */
    public Output<String> auditProfileId() {
        return this.auditProfileId;
    }

    /**
     * Specifying `monthInConsiderationGreaterThan` parameter will retrieve all items for which the event month is greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="monthInConsiderationGreaterThan")
    private @Nullable Output<String> monthInConsiderationGreaterThan;

    /**
     * @return Specifying `monthInConsiderationGreaterThan` parameter will retrieve all items for which the event month is greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> monthInConsiderationGreaterThan() {
        return Optional.ofNullable(this.monthInConsiderationGreaterThan);
    }

    /**
     * Specifying `monthInConsiderationLessThan` parameter will retrieve all items for which the event month is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="monthInConsiderationLessThan")
    private @Nullable Output<String> monthInConsiderationLessThan;

    /**
     * @return Specifying `monthInConsiderationLessThan` parameter will retrieve all items for which the event month is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> monthInConsiderationLessThan() {
        return Optional.ofNullable(this.monthInConsiderationLessThan);
    }

    /**
     * The OCID of the work request.
     * 
     */
    @Import(name="workRequestId", required=true)
    private Output<String> workRequestId;

    /**
     * @return The OCID of the work request.
     * 
     */
    public Output<String> workRequestId() {
        return this.workRequestId;
    }

    private GetAuditProfileCollectedAuditVolumeArgs() {}

    private GetAuditProfileCollectedAuditVolumeArgs(GetAuditProfileCollectedAuditVolumeArgs $) {
        this.auditProfileId = $.auditProfileId;
        this.monthInConsiderationGreaterThan = $.monthInConsiderationGreaterThan;
        this.monthInConsiderationLessThan = $.monthInConsiderationLessThan;
        this.workRequestId = $.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAuditProfileCollectedAuditVolumeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAuditProfileCollectedAuditVolumeArgs $;

        public Builder() {
            $ = new GetAuditProfileCollectedAuditVolumeArgs();
        }

        public Builder(GetAuditProfileCollectedAuditVolumeArgs defaults) {
            $ = new GetAuditProfileCollectedAuditVolumeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param auditProfileId The OCID of the audit.
         * 
         * @return builder
         * 
         */
        public Builder auditProfileId(Output<String> auditProfileId) {
            $.auditProfileId = auditProfileId;
            return this;
        }

        /**
         * @param auditProfileId The OCID of the audit.
         * 
         * @return builder
         * 
         */
        public Builder auditProfileId(String auditProfileId) {
            return auditProfileId(Output.of(auditProfileId));
        }

        /**
         * @param monthInConsiderationGreaterThan Specifying `monthInConsiderationGreaterThan` parameter will retrieve all items for which the event month is greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder monthInConsiderationGreaterThan(@Nullable Output<String> monthInConsiderationGreaterThan) {
            $.monthInConsiderationGreaterThan = monthInConsiderationGreaterThan;
            return this;
        }

        /**
         * @param monthInConsiderationGreaterThan Specifying `monthInConsiderationGreaterThan` parameter will retrieve all items for which the event month is greater than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder monthInConsiderationGreaterThan(String monthInConsiderationGreaterThan) {
            return monthInConsiderationGreaterThan(Output.of(monthInConsiderationGreaterThan));
        }

        /**
         * @param monthInConsiderationLessThan Specifying `monthInConsiderationLessThan` parameter will retrieve all items for which the event month is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder monthInConsiderationLessThan(@Nullable Output<String> monthInConsiderationLessThan) {
            $.monthInConsiderationLessThan = monthInConsiderationLessThan;
            return this;
        }

        /**
         * @param monthInConsiderationLessThan Specifying `monthInConsiderationLessThan` parameter will retrieve all items for which the event month is less than the date and time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder monthInConsiderationLessThan(String monthInConsiderationLessThan) {
            return monthInConsiderationLessThan(Output.of(monthInConsiderationLessThan));
        }

        /**
         * @param workRequestId The OCID of the work request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(Output<String> workRequestId) {
            $.workRequestId = workRequestId;
            return this;
        }

        /**
         * @param workRequestId The OCID of the work request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(String workRequestId) {
            return workRequestId(Output.of(workRequestId));
        }

        public GetAuditProfileCollectedAuditVolumeArgs build() {
            $.auditProfileId = Objects.requireNonNull($.auditProfileId, "expected parameter 'auditProfileId' to be non-null");
            $.workRequestId = Objects.requireNonNull($.workRequestId, "expected parameter 'workRequestId' to be non-null");
            return $;
        }
    }

}