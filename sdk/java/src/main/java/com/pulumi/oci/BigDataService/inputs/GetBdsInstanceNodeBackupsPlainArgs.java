// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstanceNodeBackupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstanceNodeBackupsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstanceNodeBackupsPlainArgs Empty = new GetBdsInstanceNodeBackupsPlainArgs();

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

    /**
     * The display name belonged to the node backup.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return The display name belonged to the node backup.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetBdsInstanceNodeBackupsFilter> filters;

    public Optional<List<GetBdsInstanceNodeBackupsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The node host name belonged to a node that has a node backup.
     * 
     */
    @Import(name="nodeHostName")
    private @Nullable String nodeHostName;

    /**
     * @return The node host name belonged to a node that has a node backup.
     * 
     */
    public Optional<String> nodeHostName() {
        return Optional.ofNullable(this.nodeHostName);
    }

    /**
     * The state of the Node&#39;s Backup.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The state of the Node&#39;s Backup.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetBdsInstanceNodeBackupsPlainArgs() {}

    private GetBdsInstanceNodeBackupsPlainArgs(GetBdsInstanceNodeBackupsPlainArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.nodeHostName = $.nodeHostName;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstanceNodeBackupsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstanceNodeBackupsPlainArgs $;

        public Builder() {
            $ = new GetBdsInstanceNodeBackupsPlainArgs();
        }

        public Builder(GetBdsInstanceNodeBackupsPlainArgs defaults) {
            $ = new GetBdsInstanceNodeBackupsPlainArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param displayName The display name belonged to the node backup.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetBdsInstanceNodeBackupsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetBdsInstanceNodeBackupsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param nodeHostName The node host name belonged to a node that has a node backup.
         * 
         * @return builder
         * 
         */
        public Builder nodeHostName(@Nullable String nodeHostName) {
            $.nodeHostName = nodeHostName;
            return this;
        }

        /**
         * @param state The state of the Node&#39;s Backup.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetBdsInstanceNodeBackupsPlainArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstanceNodeBackupsPlainArgs", "bdsInstanceId");
            }
            return $;
        }
    }

}
