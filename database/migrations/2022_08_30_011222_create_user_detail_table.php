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
        Schema::create('user_detail', function (Blueprint $table) {
            $table->charset = 'utf8mb4';
            $table->collation = 'utf8mb4_unicode_ci';

            $table->uuid('id')->primary();
            $table->string('user_serial', 7)->index();
            $table->enum('level', ['bronze', 'silver', 'gold', 'diamond', 'admin'])->default('bronze')->index();
            $table->integer('saldo')->default(0)->unsigned()->index();
            $table->integer('bonus')->default(0)->unsigned()->index();
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
        Schema::dropIfExists('user_detail');
    }
};
