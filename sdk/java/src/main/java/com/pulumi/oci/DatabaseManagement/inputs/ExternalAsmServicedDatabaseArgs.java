// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalAsmServicedDatabaseArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalAsmServicedDatabaseArgs Empty = new ExternalAsmServicedDatabaseArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    @Import(name="databaseSubType")
    private @Nullable Output<String> databaseSubType;

    /**
     * @return The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
     * 
     */
    public Optional<Output<String>> databaseSubType() {
        return Optional.ofNullable(this.databaseSubType);
    }

    /**
     * The type of Oracle Database installation.
     * 
     */
    @Import(name="databaseType")
    private @Nullable Output<String> databaseType;

    /**
     * @return The type of Oracle Database installation.
     * 
     */
    public Optional<Output<String>> databaseType() {
        return Optional.ofNullable(this.databaseType);
    }

    /**
     * The unique name of the external database.
     * 
     */
    @Import(name="dbUniqueName")
    private @Nullable Output<String> dbUniqueName;

    /**
     * @return The unique name of the external database.
     * 
     */
    public Optional<Output<String>> dbUniqueName() {
        return Optional.ofNullable(this.dbUniqueName);
    }

    /**
     * The list of ASM disk groups used by the database.
     * 
     */
    @Import(name="diskGroups")
    private @Nullable Output<List<String>> diskGroups;

    /**
     * @return The list of ASM disk groups used by the database.
     * 
     */
    public Optional<Output<List<String>>> diskGroups() {
        return Optional.ofNullable(this.diskGroups);
    }

    /**
     * The user-friendly name for the database. The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The user-friendly name for the database. The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Indicates whether the database is a Managed Database or not.
     * 
     */
    @Import(name="isManaged")
    private @Nullable Output<Boolean> isManaged;

    /**
     * @return Indicates whether the database is a Managed Database or not.
     * 
     */
    public Optional<Output<Boolean>> isManaged() {
        return Optional.ofNullable(this.isManaged);
    }

    private ExternalAsmServicedDatabaseArgs() {}

    private ExternalAsmServicedDatabaseArgs(ExternalAsmServicedDatabaseArgs $) {
        this.compartmentId = $.compartmentId;
        this.databaseSubType = $.databaseSubType;
        this.databaseType = $.databaseType;
        this.dbUniqueName = $.dbUniqueName;
        this.diskGroups = $.diskGroups;
        this.displayName = $.displayName;
        this.id = $.id;
        this.isManaged = $.isManaged;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalAsmServicedDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalAsmServicedDatabaseArgs $;

        public Builder() {
            $ = new ExternalAsmServicedDatabaseArgs();
        }

        public Builder(ExternalAsmServicedDatabaseArgs defaults) {
            $ = new ExternalAsmServicedDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external database resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param databaseSubType The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
         * 
         * @return builder
         * 
         */
        public Builder databaseSubType(@Nullable Output<String> databaseSubType) {
            $.databaseSubType = databaseSubType;
            return this;
        }

        /**
         * @param databaseSubType The subtype of Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, Non-container Database, Autonomous Database, or Autonomous Container Database.
         * 
         * @return builder
         * 
         */
        public Builder databaseSubType(String databaseSubType) {
            return databaseSubType(Output.of(databaseSubType));
        }

        /**
         * @param databaseType The type of Oracle Database installation.
         * 
         * @return builder
         * 
         */
        public Builder databaseType(@Nullable Output<String> databaseType) {
            $.databaseType = databaseType;
            return this;
        }

        /**
         * @param databaseType The type of Oracle Database installation.
         * 
         * @return builder
         * 
         */
        public Builder databaseType(String databaseType) {
            return databaseType(Output.of(databaseType));
        }

        /**
         * @param dbUniqueName The unique name of the external database.
         * 
         * @return builder
         * 
         */
        public Builder dbUniqueName(@Nullable Output<String> dbUniqueName) {
            $.dbUniqueName = dbUniqueName;
            return this;
        }

        /**
         * @param dbUniqueName The unique name of the external database.
         * 
         * @return builder
         * 
         */
        public Builder dbUniqueName(String dbUniqueName) {
            return dbUniqueName(Output.of(dbUniqueName));
        }

        /**
         * @param diskGroups The list of ASM disk groups used by the database.
         * 
         * @return builder
         * 
         */
        public Builder diskGroups(@Nullable Output<List<String>> diskGroups) {
            $.diskGroups = diskGroups;
            return this;
        }

        /**
         * @param diskGroups The list of ASM disk groups used by the database.
         * 
         * @return builder
         * 
         */
        public Builder diskGroups(List<String> diskGroups) {
            return diskGroups(Output.of(diskGroups));
        }

        /**
         * @param diskGroups The list of ASM disk groups used by the database.
         * 
         * @return builder
         * 
         */
        public Builder diskGroups(String... diskGroups) {
            return diskGroups(List.of(diskGroups));
        }

        /**
         * @param displayName The user-friendly name for the database. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the database. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param isManaged Indicates whether the database is a Managed Database or not.
         * 
         * @return builder
         * 
         */
        public Builder isManaged(@Nullable Output<Boolean> isManaged) {
            $.isManaged = isManaged;
            return this;
        }

        /**
         * @param isManaged Indicates whether the database is a Managed Database or not.
         * 
         * @return builder
         * 
         */
        public Builder isManaged(Boolean isManaged) {
            return isManaged(Output.of(isManaged));
        }

        public ExternalAsmServicedDatabaseArgs build() {
            return $;
        }
    }

}