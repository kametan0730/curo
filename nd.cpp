#include "nd.h"

#include "net.h"
#include "utils.h"

// TODO タイマーを追加

/**
 * NDテーブル
 * グローバル変数にテーブルを保持
 */
nd_table_entry nd_table[ND_TABLE_SIZE];

/**
 * NDテーブルにエントリの追加と更新
 * @param dev
 * @param mac_addr
 * @param ip_addr
 */
void add_nd_table_entry(net_device *dev, uint8_t *mac_addr, ipv6_addr v6_addr) {
    // 候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    const uint32_t index = (v6_addr.per_64.int1 +v6_addr.per_64.int2)  % ND_TABLE_SIZE;
    nd_table_entry *candidate = &nd_table[index];

    // テーブルに入れられるか確認
    if (candidate->v6addr.per_64.int1 + candidate->v6addr.per_64.int2 == 0 or
        candidate->v6addr.per_64.int1 == v6_addr.per_64.int1 and
        candidate->v6addr.per_64.int2 == v6_addr.per_64.int2) { // 初めの候補の場所に入れられるとき
        // エントリをセット
        memcpy(candidate->mac_addr, mac_addr, 6);
        candidate->v6addr = v6_addr;
        candidate->dev = dev;
        return;
    }

    // 入れられなかった場合は、その候補にあるエントリに連結する
    while (candidate->next != nullptr) { // 連結リストの末尾までたどる
        candidate = candidate->next;
        // 途中で同じIPアドレスのエントリがあったら、そのエントリを更新する
        if (candidate->v6addr.per_64.int1 == v6_addr.per_64.int1 and
            candidate->v6addr.per_64.int2 == v6_addr.per_64.int2) {
            memcpy(candidate->mac_addr, mac_addr, 6);
            candidate->v6addr = v6_addr;
            candidate->dev = dev;
            return;
        }
    }
    // 連結リストの末尾に新しくエントリを作成
    candidate->next = (nd_table_entry *)calloc(1, sizeof(nd_table_entry));
    memcpy(candidate->next->mac_addr, mac_addr, 6);
    candidate->next->v6addr = v6_addr;
    candidate->next->dev = dev;
}

/**
 * NDテーブルの検索
 * @param ip_addr
 */
nd_table_entry *search_nd_table_entry(ipv6_addr v6_addr) {
    // 初めの候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    nd_table_entry *candidate = &nd_table[(v6_addr.per_64.int1 +v6_addr.per_64.int2) % ND_TABLE_SIZE];

    if (candidate->v6addr.per_64.int1 == v6_addr.per_64.int1 and
            candidate->v6addr.per_64.int2 == v6_addr.per_64.int2) { // 候補のエントリが検索しているIPアドレスの物だったら
        return candidate;
    } else if (candidate->v6addr.per_64.int1 + candidate->v6addr.per_64.int2 ==
               0) { // 候補のエントリが登録されていなかったら
        return nullptr;
    }
    // 候補のエントリが検索しているIPアドレスの物でなかった場合、そのエントリの連結リストを調べる
    while (candidate->next != nullptr) {
        candidate = candidate->next;
        if (candidate->v6addr.per_64.int1 == v6_addr.per_64.int1 and
            candidate->v6addr.per_64.int2 == v6_addr.per_64.int2) { // 連結リストの中に検索しているIPアドレスの物があったら
            return candidate;
        }
    }

    // 連結リストの中に見つからなかったら
    return nullptr;
}

/**
 * NDテーブルの出力
 */
void dump_nd_table_entry() {
    printf("|--------------IPv6 ADDRESS---------------|----MAC "
           "ADDRESS----|----DEVICE-----|-INDEX-|\n");
    for (int i = 0; i < ND_TABLE_SIZE; ++i) {
        if (nd_table[i].v6addr.per_64.int1+nd_table[i].v6addr.per_64.int2 == 0) {
            continue;
        }
        // エントリの連結リストを順に出力する
        for (nd_table_entry *entry = &nd_table[i]; entry;
             entry = entry->next) {
            printf("| %37s | %14s | %13s |  %04d |\n", ipv6toascii(entry->v6addr),
                   mac_addr_toa(entry->mac_addr), entry->dev->name, i);
        }
    }
    printf("|-----------------------------------------|-------------------|---------------|-------|"
           "\n");
}