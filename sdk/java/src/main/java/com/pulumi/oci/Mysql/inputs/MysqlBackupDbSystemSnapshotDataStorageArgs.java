// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlBackupDbSystemSnapshotDataStorageArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlBackupDbSystemSnapshotDataStorageArgs Empty = new MysqlBackupDbSystemSnapshotDataStorageArgs();

    /**
     * The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
     * 
     */
    @Import(name="allocatedStorageSizeInGbs")
    private @Nullable Output<Integer> allocatedStorageSizeInGbs;

    /**
     * @return The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
     * 
     */
    public Optional<Output<Integer>> allocatedStorageSizeInGbs() {
        return Optional.ofNullable(this.allocatedStorageSizeInGbs);
    }

    /**
     * DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
     * 
     */
    @Import(name="dataStorageSizeInGb")
    private @Nullable Output<Integer> dataStorageSizeInGb;

    /**
     * @return DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
     * 
     */
    public Optional<Output<Integer>> dataStorageSizeInGb() {
        return Optional.ofNullable(this.dataStorageSizeInGb);
    }

    /**
     * The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
     * 
     */
    @Import(name="dataStorageSizeLimitInGbs")
    private @Nullable Output<Integer> dataStorageSizeLimitInGbs;

    /**
     * @return The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
     * 
     */
    public Optional<Output<Integer>> dataStorageSizeLimitInGbs() {
        return Optional.ofNullable(this.dataStorageSizeLimitInGbs);
    }

    /**
     * Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
     * 
     */
    @Import(name="isAutoExpandStorageEnabled")
    private @Nullable Output<Boolean> isAutoExpandStorageEnabled;

    /**
     * @return Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
     * 
     */
    public Optional<Output<Boolean>> isAutoExpandStorageEnabled() {
        return Optional.ofNullable(this.isAutoExpandStorageEnabled);
    }

    /**
     * Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
     * 
     */
    @Import(name="maxStorageSizeInGbs")
    private @Nullable Output<Integer> maxStorageSizeInGbs;

    /**
     * @return Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
     * 
     */
    public Optional<Output<Integer>> maxStorageSizeInGbs() {
        return Optional.ofNullable(this.maxStorageSizeInGbs);
    }

    private MysqlBackupDbSystemSnapshotDataStorageArgs() {}

    private MysqlBackupDbSystemSnapshotDataStorageArgs(MysqlBackupDbSystemSnapshotDataStorageArgs $) {
        this.allocatedStorageSizeInGbs = $.allocatedStorageSizeInGbs;
        this.dataStorageSizeInGb = $.dataStorageSizeInGb;
        this.dataStorageSizeLimitInGbs = $.dataStorageSizeLimitInGbs;
        this.isAutoExpandStorageEnabled = $.isAutoExpandStorageEnabled;
        this.maxStorageSizeInGbs = $.maxStorageSizeInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlBackupDbSystemSnapshotDataStorageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlBackupDbSystemSnapshotDataStorageArgs $;

        public Builder() {
            $ = new MysqlBackupDbSystemSnapshotDataStorageArgs();
        }

        public Builder(MysqlBackupDbSystemSnapshotDataStorageArgs defaults) {
            $ = new MysqlBackupDbSystemSnapshotDataStorageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allocatedStorageSizeInGbs The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
         * 
         * @return builder
         * 
         */
        public Builder allocatedStorageSizeInGbs(@Nullable Output<Integer> allocatedStorageSizeInGbs) {
            $.allocatedStorageSizeInGbs = allocatedStorageSizeInGbs;
            return this;
        }

        /**
         * @param allocatedStorageSizeInGbs The actual allocated storage size for the DB System. This may be higher than dataStorageSizeInGBs if an automatic storage expansion has occurred.
         * 
         * @return builder
         * 
         */
        public Builder allocatedStorageSizeInGbs(Integer allocatedStorageSizeInGbs) {
            return allocatedStorageSizeInGbs(Output.of(allocatedStorageSizeInGbs));
        }

        /**
         * @param dataStorageSizeInGb DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeInGb(@Nullable Output<Integer> dataStorageSizeInGb) {
            $.dataStorageSizeInGb = dataStorageSizeInGb;
            return this;
        }

        /**
         * @param dataStorageSizeInGb DEPRECATED: User specified size of the data volume. May be less than current allocatedStorageSizeInGBs. Replaced by dataStorage.dataStorageSizeInGBs.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeInGb(Integer dataStorageSizeInGb) {
            return dataStorageSizeInGb(Output.of(dataStorageSizeInGb));
        }

        /**
         * @param dataStorageSizeLimitInGbs The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeLimitInGbs(@Nullable Output<Integer> dataStorageSizeLimitInGbs) {
            $.dataStorageSizeLimitInGbs = dataStorageSizeLimitInGbs;
            return this;
        }

        /**
         * @param dataStorageSizeLimitInGbs The absolute limit the DB System&#39;s storage size may ever expand to, either manually or automatically. This limit is based based on the initial dataStorageSizeInGBs when the DB System was first created. Both dataStorageSizeInGBs and maxDataStorageSizeInGBs can not exceed this value.
         * 
         * @return builder
         * 
         */
        public Builder dataStorageSizeLimitInGbs(Integer dataStorageSizeLimitInGbs) {
            return dataStorageSizeLimitInGbs(Output.of(dataStorageSizeLimitInGbs));
        }

        /**
         * @param isAutoExpandStorageEnabled Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
         * 
         * @return builder
         * 
         */
        public Builder isAutoExpandStorageEnabled(@Nullable Output<Boolean> isAutoExpandStorageEnabled) {
            $.isAutoExpandStorageEnabled = isAutoExpandStorageEnabled;
            return this;
        }

        /**
         * @param isAutoExpandStorageEnabled Enable/disable automatic storage expansion. When set to true, the DB System will automatically add storage incrementally up to the value specified in maxStorageSizeInGBs.
         * 
         * @return builder
         * 
         */
        public Builder isAutoExpandStorageEnabled(Boolean isAutoExpandStorageEnabled) {
            return isAutoExpandStorageEnabled(Output.of(isAutoExpandStorageEnabled));
        }

        /**
         * @param maxStorageSizeInGbs Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
         * 
         * @return builder
         * 
         */
        public Builder maxStorageSizeInGbs(@Nullable Output<Integer> maxStorageSizeInGbs) {
            $.maxStorageSizeInGbs = maxStorageSizeInGbs;
            return this;
        }

        /**
         * @param maxStorageSizeInGbs Maximum storage size this DB System can expand to. When isAutoExpandStorageEnabled is set to true, the DB System will add storage incrementally up to this value.
         * 
         * @return builder
         * 
         */
        public Builder maxStorageSizeInGbs(Integer maxStorageSizeInGbs) {
            return maxStorageSizeInGbs(Output.of(maxStorageSizeInGbs));
        }

        public MysqlBackupDbSystemSnapshotDataStorageArgs build() {
            return $;
        }
    }

}
