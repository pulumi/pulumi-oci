// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.GetMysqlBackupsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMysqlBackupsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMysqlBackupsArgs Empty = new GetMysqlBackupsArgs();

    /**
     * Backup OCID
     * 
     */
    @Import(name="backupId")
    private @Nullable Output<String> backupId;

    /**
     * @return Backup OCID
     * 
     */
    public Optional<Output<String>> backupId() {
        return Optional.ofNullable(this.backupId);
    }

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Backup creationType
     * 
     */
    @Import(name="creationType")
    private @Nullable Output<String> creationType;

    /**
     * @return Backup creationType
     * 
     */
    public Optional<Output<String>> creationType() {
        return Optional.ofNullable(this.creationType);
    }

    /**
     * The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable Output<String> dbSystemId;

    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    /**
     * A filter to return only the resource matching the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetMysqlBackupsFilterArgs>> filters;

    public Optional<Output<List<GetMysqlBackupsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Backup Lifecycle State
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return Backup Lifecycle State
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetMysqlBackupsArgs() {}

    private GetMysqlBackupsArgs(GetMysqlBackupsArgs $) {
        this.backupId = $.backupId;
        this.compartmentId = $.compartmentId;
        this.creationType = $.creationType;
        this.dbSystemId = $.dbSystemId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMysqlBackupsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMysqlBackupsArgs $;

        public Builder() {
            $ = new GetMysqlBackupsArgs();
        }

        public Builder(GetMysqlBackupsArgs defaults) {
            $ = new GetMysqlBackupsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backupId Backup OCID
         * 
         * @return builder
         * 
         */
        public Builder backupId(@Nullable Output<String> backupId) {
            $.backupId = backupId;
            return this;
        }

        /**
         * @param backupId Backup OCID
         * 
         * @return builder
         * 
         */
        public Builder backupId(String backupId) {
            return backupId(Output.of(backupId));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param creationType Backup creationType
         * 
         * @return builder
         * 
         */
        public Builder creationType(@Nullable Output<String> creationType) {
            $.creationType = creationType;
            return this;
        }

        /**
         * @param creationType Backup creationType
         * 
         * @return builder
         * 
         */
        public Builder creationType(String creationType) {
            return creationType(Output.of(creationType));
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        /**
         * @param displayName A filter to return only the resource matching the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resource matching the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetMysqlBackupsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetMysqlBackupsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetMysqlBackupsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state Backup Lifecycle State
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state Backup Lifecycle State
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetMysqlBackupsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}