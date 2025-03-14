// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.inputs.GetJavaDownloadsJavaDownloadReportsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetJavaDownloadsJavaDownloadReportsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJavaDownloadsJavaDownloadReportsArgs Empty = new GetJavaDownloadsJavaDownloadReportsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetJavaDownloadsJavaDownloadReportsFilterArgs>> filters;

    public Optional<Output<List<GetJavaDownloadsJavaDownloadReportsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique Java download report identifier.
     * 
     */
    @Import(name="javaDownloadReportId")
    private @Nullable Output<String> javaDownloadReportId;

    /**
     * @return Unique Java download report identifier.
     * 
     */
    public Optional<Output<String>> javaDownloadReportId() {
        return Optional.ofNullable(this.javaDownloadReportId);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetJavaDownloadsJavaDownloadReportsArgs() {}

    private GetJavaDownloadsJavaDownloadReportsArgs(GetJavaDownloadsJavaDownloadReportsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.javaDownloadReportId = $.javaDownloadReportId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJavaDownloadsJavaDownloadReportsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJavaDownloadsJavaDownloadReportsArgs $;

        public Builder() {
            $ = new GetJavaDownloadsJavaDownloadReportsArgs();
        }

        public Builder(GetJavaDownloadsJavaDownloadReportsArgs defaults) {
            $ = new GetJavaDownloadsJavaDownloadReportsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetJavaDownloadsJavaDownloadReportsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetJavaDownloadsJavaDownloadReportsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetJavaDownloadsJavaDownloadReportsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param javaDownloadReportId Unique Java download report identifier.
         * 
         * @return builder
         * 
         */
        public Builder javaDownloadReportId(@Nullable Output<String> javaDownloadReportId) {
            $.javaDownloadReportId = javaDownloadReportId;
            return this;
        }

        /**
         * @param javaDownloadReportId Unique Java download report identifier.
         * 
         * @return builder
         * 
         */
        public Builder javaDownloadReportId(String javaDownloadReportId) {
            return javaDownloadReportId(Output.of(javaDownloadReportId));
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetJavaDownloadsJavaDownloadReportsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetJavaDownloadsJavaDownloadReportsArgs", "compartmentId");
            }
            return $;
        }
    }

}
