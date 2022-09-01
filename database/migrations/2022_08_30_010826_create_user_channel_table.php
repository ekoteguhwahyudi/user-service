<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('user_channel', function (Blueprint $table) {
            $table->charset = 'utf8mb4';
            $table->collation = 'utf8mb4_unicode_ci';

            $table->uuid('id')->primary();
            $table->string('serial', 7)->unique()->index();
            $table->string('category', 100)->default('whatsapp')->index()->comment("whatsapp,telegram,sms,line, dll");
            $table->string('description')->nullable()->index();
            $table->string('status')->default(1)->index();
            $table->uuid('created_by')->nullable()->comment('user id');
            $table->uuid('updated_by')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('user_channel');
    }
};
