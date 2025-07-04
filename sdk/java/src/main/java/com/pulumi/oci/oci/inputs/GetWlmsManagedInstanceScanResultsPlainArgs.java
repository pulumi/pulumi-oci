// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.inputs.GetWlmsManagedInstanceScanResultsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetWlmsManagedInstanceScanResultsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWlmsManagedInstanceScanResultsPlainArgs Empty = new GetWlmsManagedInstanceScanResultsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetWlmsManagedInstanceScanResultsFilter> filters;

    public Optional<List<GetWlmsManagedInstanceScanResultsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    @Import(name="managedInstanceId", required=true)
    private String managedInstanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
     * 
     */
    public String managedInstanceId() {
        return this.managedInstanceId;
    }

    /**
     * The name of the server.
     * 
     */
    @Import(name="serverName")
    private @Nullable String serverName;

    /**
     * @return The name of the server.
     * 
     */
    public Optional<String> serverName() {
        return Optional.ofNullable(this.serverName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     * 
     */
    @Import(name="wlsDomainId")
    private @Nullable String wlsDomainId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
     * 
     */
    public Optional<String> wlsDomainId() {
        return Optional.ofNullable(this.wlsDomainId);
    }

    private GetWlmsManagedInstanceScanResultsPlainArgs() {}

    private GetWlmsManagedInstanceScanResultsPlainArgs(GetWlmsManagedInstanceScanResultsPlainArgs $) {
        this.filters = $.filters;
        this.managedInstanceId = $.managedInstanceId;
        this.serverName = $.serverName;
        this.wlsDomainId = $.wlsDomainId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWlmsManagedInstanceScanResultsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWlmsManagedInstanceScanResultsPlainArgs $;

        public Builder() {
            $ = new GetWlmsManagedInstanceScanResultsPlainArgs();
        }

        public Builder(GetWlmsManagedInstanceScanResultsPlainArgs defaults) {
            $ = new GetWlmsManagedInstanceScanResultsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetWlmsManagedInstanceScanResultsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetWlmsManagedInstanceScanResultsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param managedInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param serverName The name of the server.
         * 
         * @return builder
         * 
         */
        public Builder serverName(@Nullable String serverName) {
            $.serverName = serverName;
            return this;
        }

        /**
         * @param wlsDomainId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
         * 
         * @return builder
         * 
         */
        public Builder wlsDomainId(@Nullable String wlsDomainId) {
            $.wlsDomainId = wlsDomainId;
            return this;
        }

        public GetWlmsManagedInstanceScanResultsPlainArgs build() {
            if ($.managedInstanceId == null) {
                throw new MissingRequiredPropertyException("GetWlmsManagedInstanceScanResultsPlainArgs", "managedInstanceId");
            }
            return $;
        }
    }

}
